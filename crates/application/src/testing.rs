//! In-memory fakes of the ports.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use larder_server_domain::{Household, SyncRecord, User, incoming_wins};
use uuid::Uuid;

use crate::auth::AuthService;
use crate::error::ServerResult;
use crate::households::HouseholdService;
use crate::ports::*;
use crate::sync::SyncService;

#[derive(Default)]
pub struct MemUsers(Mutex<Vec<User>>);

impl MemUsers {
    pub fn all(&self) -> Vec<User> {
        self.0.lock().unwrap().clone()
    }
    pub fn clear(&self) {
        self.0.lock().unwrap().clear();
    }
}

#[async_trait]
impl UserRepository for MemUsers {
    async fn find_by_username(&self, username: &str) -> ServerResult<Option<User>> {
        Ok(self.all().into_iter().find(|u| u.username == username))
    }
    async fn find_by_id(&self, id: Uuid) -> ServerResult<Option<User>> {
        Ok(self.all().into_iter().find(|u| u.id == id))
    }
    async fn insert(&self, user: &User) -> ServerResult<bool> {
        let mut users = self.0.lock().unwrap();
        if users.iter().any(|u| u.username == user.username) {
            return Ok(false);
        }
        users.push(user.clone());
        Ok(true)
    }
    async fn set_household(&self, user_id: Uuid, household_id: Uuid) -> ServerResult<()> {
        for user in self
            .0
            .lock()
            .unwrap()
            .iter_mut()
            .filter(|u| u.id == user_id)
        {
            user.household_id = Some(household_id);
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct MemHouseholds(Mutex<Vec<Household>>);

#[async_trait]
impl HouseholdRepository for MemHouseholds {
    async fn insert(&self, household: &Household) -> ServerResult<()> {
        self.0.lock().unwrap().push(household.clone());
        Ok(())
    }
    async fn find_by_id(&self, id: Uuid) -> ServerResult<Option<Household>> {
        Ok(self.0.lock().unwrap().iter().find(|h| h.id == id).cloned())
    }
    async fn find_by_invite_code(&self, code: &str) -> ServerResult<Option<Household>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .iter()
            .find(|h| h.invite_code == code)
            .cloned())
    }
}

#[derive(Default)]
pub struct MemRecords {
    rows: Mutex<Vec<(Uuid, Sequenced)>>,
}

#[async_trait]
impl RecordRepository for MemRecords {
    async fn store_newer(&self, household_id: Uuid, records: &[SyncRecord]) -> ServerResult<usize> {
        let mut rows = self.rows.lock().unwrap();
        let mut accepted = 0;
        for record in records {
            let existing = rows.iter().position(|(h, s)| {
                *h == household_id && s.record.kind == record.kind && s.record.id == record.id
            });
            let stored = existing.map(|i| rows[i].1.record.updated_at);
            if !incoming_wins(stored, record.updated_at) {
                continue;
            }
            // Change numbers only ever grow, so compute the next one before
            // dropping the replaced version.
            let seq = rows.iter().map(|(_, s)| s.seq).max().unwrap_or(0) + 1;
            if let Some(i) = existing {
                rows.remove(i);
            }
            rows.push((
                household_id,
                Sequenced {
                    seq,
                    record: record.clone(),
                },
            ));
            accepted += 1;
        }
        Ok(accepted)
    }

    async fn changed_since(
        &self,
        household_id: Uuid,
        cursor: i64,
        limit: usize,
    ) -> ServerResult<Vec<Sequenced>> {
        let mut found: Vec<Sequenced> = self
            .rows
            .lock()
            .unwrap()
            .iter()
            .filter(|(h, s)| *h == household_id && s.seq > cursor)
            .map(|(_, s)| s.clone())
            .collect();
        found.sort_by_key(|s| s.seq);
        found.truncate(limit);
        Ok(found)
    }
}

/// Reversible "hash", enough to check that the plain password is not stored.
pub struct FakeHasher;

#[async_trait]
impl PasswordHasher for FakeHasher {
    async fn hash(&self, password: &str) -> ServerResult<String> {
        Ok(format!(
            "hashed:{}",
            password.chars().rev().collect::<String>()
        ))
    }
    async fn verify(&self, password: &str, hash: &str) -> ServerResult<bool> {
        Ok(self.hash(password).await? == hash)
    }
}

pub struct FakeTokens;

impl TokenService for FakeTokens {
    fn issue(&self, user_id: Uuid) -> ServerResult<String> {
        Ok(format!("token:{user_id}"))
    }
    fn verify(&self, token: &str) -> Option<Uuid> {
        token.strip_prefix("token:")?.parse().ok()
    }
}

/// Distinct, predictable ids.
#[derive(Default)]
pub struct CountingIds(AtomicU64);

impl IdGenerator for CountingIds {
    fn random(&self) -> Uuid {
        let n = self.0.fetch_add(1, Ordering::SeqCst) + 1;
        // Spread the counter over the leading bytes, which is where the
        // invite code is derived from.
        Uuid::from_u128(u128::from(n).wrapping_mul(0x0123_4567_89AB_CDEF_1357_9BDF_0246_8ACE))
    }
}

#[derive(Default)]
pub struct Fakes {
    pub users: Arc<MemUsers>,
    pub households: Arc<MemHouseholds>,
    pub records: Arc<MemRecords>,
    pub ids: Arc<CountingIds>,
}

impl Fakes {
    pub fn auth(&self, allow_registration: bool) -> AuthService {
        AuthService::new(
            self.users.clone(),
            Arc::new(FakeHasher),
            Arc::new(FakeTokens),
            self.ids.clone(),
            allow_registration,
        )
    }

    pub fn households(&self) -> HouseholdService {
        HouseholdService::new(
            self.households.clone(),
            self.users.clone(),
            self.ids.clone(),
        )
    }

    pub fn sync(&self) -> SyncService {
        SyncService::new(self.records.clone())
    }

    /// Registers a user and returns it.
    pub async fn user(&self, name: &str) -> User {
        let auth = self.auth(true);
        let token = auth.register(name, "longenough").await.unwrap();
        auth.authenticate(&token).await.unwrap()
    }

    pub async fn reload(&self, user: &User) -> User {
        self.users.find_by_id(user.id).await.unwrap().unwrap()
    }
}
