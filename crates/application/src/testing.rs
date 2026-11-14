//! In-memory fakes of the ports.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use larder_server_domain::session::Session;
use larder_server_domain::{Household, SyncRecord, User, incoming_wins};
use uuid::Uuid;

use crate::auth::{AuthPorts, AuthService};
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

#[derive(Default)]
pub struct MemSessions(Mutex<Vec<(String, Session)>>);

impl MemSessions {
    pub fn keys(&self) -> Vec<String> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .map(|(k, _)| k.clone())
            .collect()
    }
}

#[async_trait]
impl SessionRepository for MemSessions {
    async fn create(&self, token_hash: &str, session: &Session) -> ServerResult<()> {
        self.0
            .lock()
            .unwrap()
            .push((token_hash.to_string(), session.clone()));
        Ok(())
    }
    async fn find(&self, token_hash: &str) -> ServerResult<Option<Session>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .iter()
            .find(|(k, _)| k == token_hash)
            .map(|(_, s)| s.clone()))
    }
    async fn touch(&self, token_hash: &str, now: i64) -> ServerResult<()> {
        for (_, s) in self
            .0
            .lock()
            .unwrap()
            .iter_mut()
            .filter(|(k, _)| k == token_hash)
        {
            s.last_used_at = now;
        }
        Ok(())
    }
    async fn delete(&self, token_hash: &str) -> ServerResult<()> {
        self.0.lock().unwrap().retain(|(k, _)| k != token_hash);
        Ok(())
    }
    async fn delete_for_user(&self, user_id: Uuid) -> ServerResult<u64> {
        let mut rows = self.0.lock().unwrap();
        let before = rows.len();
        rows.retain(|(_, s)| s.user_id != user_id);
        Ok((before - rows.len()) as u64)
    }
    async fn purge(&self, idle_cutoff: i64, created_cutoff: i64) -> ServerResult<u64> {
        let mut rows = self.0.lock().unwrap();
        let before = rows.len();
        rows.retain(|(_, s)| s.last_used_at > idle_cutoff && s.created_at > created_cutoff);
        Ok((before - rows.len()) as u64)
    }
}

/// Reversible "hash", enough to check that the plain password is not stored.
/// Counts verifications, to check that every sign-in checks a password.
#[derive(Default)]
pub struct FakeHasher(AtomicU64);

impl FakeHasher {
    pub fn verifications(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl PasswordHasher for FakeHasher {
    async fn hash(&self, password: &str) -> ServerResult<String> {
        Ok(format!(
            "hashed:{}",
            password.chars().rev().collect::<String>()
        ))
    }
    async fn verify(&self, password: &str, hash: &str) -> ServerResult<bool> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(self.hash(password).await? == hash)
    }
}

/// Sequential tokens; the "hash" is a visible transformation.
#[derive(Default)]
pub struct FakeTokens(AtomicU64);

impl SessionTokens for FakeTokens {
    fn generate(&self) -> String {
        format!("token{}", self.0.fetch_add(1, Ordering::SeqCst))
    }
    fn hash(&self, token: &str) -> String {
        format!("hash-of-{token}")
    }
}

/// A clock that only moves when told to.
pub struct FakeClock(AtomicI64);

impl Default for FakeClock {
    fn default() -> Self {
        Self(AtomicI64::new(1_800_000_000))
    }
}

impl FakeClock {
    pub fn advance(&self, secs: i64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for FakeClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
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
    pub sessions: Arc<MemSessions>,
    pub hasher: Arc<FakeHasher>,
    pub tokens: Arc<FakeTokens>,
    pub clock: Arc<FakeClock>,
    pub ids: Arc<CountingIds>,
}

impl Fakes {
    pub fn auth(&self, allow_registration: bool) -> AuthService {
        AuthService::new(
            AuthPorts {
                users: self.users.clone(),
                sessions: self.sessions.clone(),
                hasher: self.hasher.clone(),
                tokens: self.tokens.clone(),
                ids: self.ids.clone(),
                clock: self.clock.clone(),
            },
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
        let token = auth.register(name, "longenough", None).await.unwrap();
        auth.authenticate(&token).await.unwrap()
    }

    pub async fn reload(&self, user: &User) -> User {
        self.users.find_by_id(user.id).await.unwrap().unwrap()
    }
}
