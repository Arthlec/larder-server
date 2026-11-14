use async_trait::async_trait;
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

pub trait TokenService: Send + Sync {
    fn issue(&self, user_id: Uuid) -> ServerResult<String>;
    /// The user id, if the token is genuine and not expired.
    fn verify(&self, token: &str) -> Option<Uuid>;
}

/// Source of random ids (v4). A port so tests are deterministic.
pub trait IdGenerator: Send + Sync {
    fn random(&self) -> Uuid;
}
