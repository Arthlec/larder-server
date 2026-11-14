use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::password_hash::{PasswordHash, PasswordHasher as _, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use larder_server_application::error::{ServerError, ServerResult};
use larder_server_application::ports::{Clock, IdGenerator, PasswordHasher, SessionTokens};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;
use uuid::Uuid;

fn internal(e: impl std::fmt::Display) -> ServerError {
    ServerError::Internal(e.to_string())
}

/// Hashes computed at the same time, at most. Each one holds
/// [`MEMORY_KIB`] of memory, so this bounds the server's memory use and
/// keeps a burst of sign-ins from starving a small machine.
const CONCURRENT_HASHES: usize = 2;

/// RFC 9106's second recommended setting for Argon2id is 64 MiB with three
/// passes; OWASP's minimum is 19 MiB with two. This uses the RFC's.
const MEMORY_KIB: u32 = 64 * 1024;
const PASSES: u32 = 3;
/// One lane: the `argon2` crate fills lanes one after the other on one
/// thread, so more lanes would take as long and only help an attacker with
/// parallel hardware.
const LANES: u32 = 1;

/// Argon2id password hashing, run off the async threads because it is
/// deliberately slow.
#[derive(Clone)]
pub struct Argon2Hasher {
    params: Params,
    permits: Arc<Semaphore>,
}

impl Argon2Hasher {
    /// 64 MiB, 3 passes, 1 lane (see the constants above).
    pub fn new() -> Self {
        Self::with(Params::new(MEMORY_KIB, PASSES, LANES, None).expect("valid argon2 parameters"))
    }

    /// Minimal cost. Only for tests, where hashing speed matters and
    /// strength does not.
    pub fn insecure_fast() -> Self {
        Self::with(Params::new(8, 1, 1, None).expect("valid argon2 parameters"))
    }

    fn with(params: Params) -> Self {
        Self {
            params,
            permits: Arc::new(Semaphore::new(CONCURRENT_HASHES)),
        }
    }

    fn argon(&self) -> Argon2<'static> {
        Argon2::new(Algorithm::Argon2id, Version::V0x13, self.params.clone())
    }

    async fn run<T: Send + 'static>(
        &self,
        work: impl FnOnce(Argon2<'static>) -> ServerResult<T> + Send + 'static,
    ) -> ServerResult<T> {
        let _permit = self.permits.acquire().await.map_err(internal)?;
        let argon = self.argon();
        tokio::task::spawn_blocking(move || work(argon))
            .await
            .map_err(internal)?
    }
}

impl Default for Argon2Hasher {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PasswordHasher for Argon2Hasher {
    async fn hash(&self, password: &str) -> ServerResult<String> {
        let password = password.to_string();
        self.run(move |argon| {
            let mut salt = [0u8; 16];
            getrandom::getrandom(&mut salt).map_err(internal)?;
            let salt = SaltString::encode_b64(&salt).map_err(internal)?;
            argon
                .hash_password(password.as_bytes(), &salt)
                .map(|h| h.to_string())
                .map_err(internal)
        })
        .await
    }

    async fn verify(&self, password: &str, hash: &str) -> ServerResult<bool> {
        let password = password.to_string();
        let hash = hash.to_string();
        self.run(move |argon| {
            let parsed = PasswordHash::new(&hash).map_err(internal)?;
            Ok(argon.verify_password(password.as_bytes(), &parsed).is_ok())
        })
        .await
    }
}

/// Session tokens: 256 bits from the operating system's secure random
/// source, base64url. Stored as their SHA-256, so the database alone does
/// not let anyone sign in. A plain (unsalted) hash is enough because the
/// token is random, unlike a password.
pub struct RandomTokens;

impl SessionTokens for RandomTokens {
    fn generate(&self) -> String {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).expect("the operating system's random source works");
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn hash(&self, token: &str) -> String {
        hex(&Sha256::digest(token.as_bytes()))
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }
}

pub struct RandomIds;

impl IdGenerator for RandomIds {
    fn random(&self) -> Uuid {
        Uuid::new_v4()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hash_verifies_only_the_right_password() {
        let hasher = Argon2Hasher::insecure_fast();
        let hash = hasher.hash("correct horse").await.unwrap();
        assert!(hash.starts_with("$argon2id$v=19$"));
        assert!(hasher.verify("correct horse", &hash).await.unwrap());
        assert!(!hasher.verify("wrong horse", &hash).await.unwrap());
    }

    #[tokio::test]
    async fn same_password_hashes_differently_each_time() {
        let hasher = Argon2Hasher::insecure_fast();
        assert_ne!(
            hasher.hash("pw").await.unwrap(),
            hasher.hash("pw").await.unwrap()
        );
    }

    #[tokio::test]
    async fn production_parameters_are_in_the_hash_and_interoperate() {
        let hash = Argon2Hasher::new().hash("pw").await.unwrap();
        assert!(
            hash.starts_with("$argon2id$v=19$m=65536,t=3,p=1$"),
            "{hash}"
        );
        // The parameters are in the hash, so any instance can verify it.
        assert!(
            Argon2Hasher::insecure_fast()
                .verify("pw", &hash)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn corrupt_stored_hash_is_an_error_not_a_match() {
        assert!(
            Argon2Hasher::insecure_fast()
                .verify("pw", "garbage")
                .await
                .is_err()
        );
    }

    #[test]
    fn tokens_are_long_random_and_url_safe() {
        let a = RandomTokens.generate();
        assert_eq!(a.len(), 43);
        assert!(
            a.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
        assert_ne!(a, RandomTokens.generate());
    }

    #[test]
    fn token_hash_is_sha256_hex() {
        // Known SHA-256 of "abc".
        assert_eq!(
            RandomTokens.hash("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn random_ids_differ() {
        assert_ne!(RandomIds.random(), RandomIds.random());
    }
}
