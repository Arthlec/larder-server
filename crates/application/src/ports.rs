use async_trait::async_trait;
use larder_server_domain::session::Session;
use larder_server_domain::{Household, SyncRecord, User};
use uuid::Uuid;

use crate::error::ServerResult;

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn find_by_username(&self, username: &str) -> ServerResult<Option<User>>;
    async fn find_by_id(&self, id: Uuid) -> ServerResult<Option<User>>;
    /// Returns `false` (and stores nothing) if the username is taken.
    async fn insert(&self, user: &User) -> ServerResult<bool>;
    async fn set_household(&self, user_id: Uuid, household_id: Uuid) -> ServerResult<()>;
}

/// Signed-in sessions, keyed by the hash of their token: the plain token
/// is never stored.
#[async_trait]
pub trait SessionRepository: Send + Sync {
    async fn create(&self, token_hash: &str, session: &Session) -> ServerResult<()>;
    async fn find(&self, token_hash: &str) -> ServerResult<Option<Session>>;
    async fn touch(&self, token_hash: &str, now: i64) -> ServerResult<()>;
    async fn delete(&self, token_hash: &str) -> ServerResult<()>;
    /// Returns how many were deleted.
    async fn delete_for_user(&self, user_id: Uuid) -> ServerResult<u64>;
    /// Deletes sessions last used before `idle_cutoff` or created before
    /// `created_cutoff`. Returns how many.
    async fn purge(&self, idle_cutoff: i64, created_cutoff: i64) -> ServerResult<u64>;
}

#[async_trait]
pub trait HouseholdRepository: Send + Sync {
    async fn insert(&self, household: &Household) -> ServerResult<()>;
    async fn find_by_id(&self, id: Uuid) -> ServerResult<Option<Household>>;
    async fn find_by_invite_code(&self, code: &str) -> ServerResult<Option<Household>>;
}

/// A stored record with the server-assigned change number used as cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sequenced {
    pub seq: i64,
    pub record: SyncRecord,
}

#[async_trait]
pub trait RecordRepository: Send + Sync {
    /// Stores each record that wins over the stored version
    /// (`larder_server_domain::incoming_wins`), giving it a new, higher
    /// change number. All or nothing. Returns how many were stored.
    async fn store_newer(&self, household_id: Uuid, records: &[SyncRecord]) -> ServerResult<usize>;
    /// Records with a change number above `cursor`, lowest first.
    async fn changed_since(
        &self,
        household_id: Uuid,
        cursor: i64,
        limit: usize,
    ) -> ServerResult<Vec<Sequenced>>;
}

#[async_trait]
pub trait PasswordHasher: Send + Sync {
    async fn hash(&self, password: &str) -> ServerResult<String>;
    async fn verify(&self, password: &str, hash: &str) -> ServerResult<bool>;
}

/// Session tokens: unguessable random strings, stored only as a hash.
pub trait SessionTokens: Send + Sync {
    fn generate(&self) -> String;
    fn hash(&self, token: &str) -> String;
}

/// Seconds since the Unix epoch.
pub trait Clock: Send + Sync {
    fn now(&self) -> i64;
}

/// Source of random ids (v4). A port so tests are deterministic.
pub trait IdGenerator: Send + Sync {
    fn random(&self) -> Uuid;
}
