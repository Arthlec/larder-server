use std::time::{Duration, SystemTime, UNIX_EPOCH};

use argon2::password_hash::{PasswordHash, PasswordHasher as _, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use async_trait::async_trait;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use larder_server_application::error::{ServerError, ServerResult};
use larder_server_application::ports::{IdGenerator, PasswordHasher, TokenService};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

fn internal(e: impl std::fmt::Display) -> ServerError {
    ServerError::Internal(e.to_string())
}

/// Argon2id password hashing, run off the async threads because it is
/// deliberately slow.
#[derive(Clone)]
pub struct Argon2Hasher {
    params: Params,
}

impl Argon2Hasher {
    /// The crate's recommended parameters (19 MiB, 2 passes).
    pub fn new() -> Self {
        Self {
            params: Params::default(),
        }
    }

    /// Minimal cost. Only for tests, where hashing speed matters and
    /// strength does not.
    pub fn insecure_fast() -> Self {
        Self {
            params: Params::new(8, 1, 1, None).expect("valid argon2 parameters"),
        }
    }

    fn argon(&self) -> Argon2<'static> {
        Argon2::new(Algorithm::Argon2id, Version::V0x13, self.params.clone())
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
        let argon = self.argon();
        let password = password.to_string();
        tokio::task::spawn_blocking(move || {
            // A v4 UUID is 122 bits from the operating system's secure
            // random source: ample for a salt, which only has to be unique.
            let salt = SaltString::encode_b64(Uuid::new_v4().as_bytes()).map_err(internal)?;
            argon
                .hash_password(password.as_bytes(), &salt)
                .map(|h| h.to_string())
                .map_err(internal)
        })
        .await
        .map_err(internal)?
    }

    async fn verify(&self, password: &str, hash: &str) -> ServerResult<bool> {
        let argon = self.argon();
        let password = password.to_string();
        let hash = hash.to_string();
        tokio::task::spawn_blocking(move || {
            let parsed = PasswordHash::new(&hash).map_err(internal)?;
            Ok(argon.verify_password(password.as_bytes(), &parsed).is_ok())
        })
        .await
        .map_err(internal)?
    }
}

#[derive(Serialize, Deserialize)]
struct Claims {
    /// User id.
    sub: String,
    /// Expiry, seconds since the Unix epoch.
    exp: u64,
}

/// Signed (HS256) access tokens.
pub struct JwtTokens {
    encoding: EncodingKey,
    decoding: DecodingKey,
    lifetime: Duration,
}

impl JwtTokens {
    pub fn new(secret: &str, lifetime: Duration) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret.as_bytes()),
            decoding: DecodingKey::from_secret(secret.as_bytes()),
            lifetime,
        }
    }
}

impl TokenService for JwtTokens {
    fn issue(&self, user_id: Uuid) -> ServerResult<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(internal)?;
        let claims = Claims {
            sub: user_id.to_string(),
            exp: (now + self.lifetime).as_secs(),
        };
        jsonwebtoken::encode(&Header::default(), &claims, &self.encoding).map_err(internal)
    }

    fn verify(&self, token: &str) -> Option<Uuid> {
        let mut validation = Validation::default();
        validation.leeway = 0;
        jsonwebtoken::decode::<Claims>(token, &self.decoding, &validation)
            .ok()?
            .claims
            .sub
            .parse()
            .ok()
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
        assert!(hash.starts_with("$argon2id$"));
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
    async fn default_parameters_work_and_interoperate() {
        let hash = Argon2Hasher::new().hash("pw").await.unwrap();
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
    fn token_round_trips() {
        let tokens = JwtTokens::new("secret", Duration::from_secs(60));
        let id = Uuid::new_v4();
        assert_eq!(tokens.verify(&tokens.issue(id).unwrap()), Some(id));
    }

    #[test]
    fn token_signed_with_another_secret_is_rejected() {
        let ours = JwtTokens::new("secret", Duration::from_secs(60));
        let theirs = JwtTokens::new("other", Duration::from_secs(60));
        assert_eq!(ours.verify(&theirs.issue(Uuid::new_v4()).unwrap()), None);
        assert_eq!(ours.verify("garbage"), None);
    }

    #[test]
    fn expired_token_is_rejected() {
        let tokens = JwtTokens::new("secret", Duration::from_secs(60));
        let expired = jsonwebtoken::encode(
            &Header::default(),
            &Claims {
                sub: Uuid::new_v4().to_string(),
                exp: 1,
            },
            &tokens.encoding,
        )
        .unwrap();
        assert_eq!(tokens.verify(&expired), None);
    }

    #[test]
    fn random_ids_differ() {
        assert_ne!(RandomIds.random(), RandomIds.random());
    }
}
