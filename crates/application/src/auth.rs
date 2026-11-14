use std::net::IpAddr;
use std::sync::{Arc, OnceLock};

use larder_server_domain::lockout::LockoutPolicy;
use larder_server_domain::session::{Session, expiry_cutoffs};
use larder_server_domain::{User, validate_password, validate_username};

use crate::error::{ServerError, ServerResult};
use crate::ports::{
    Clock, IdGenerator, PasswordHasher, SessionRepository, SessionTokens, UserRepository,
};
use crate::throttle::Throttle;

/// The adapters [`AuthService`] needs.
pub struct AuthPorts {
    pub users: Arc<dyn UserRepository>,
    pub sessions: Arc<dyn SessionRepository>,
    pub hasher: Arc<dyn PasswordHasher>,
    pub tokens: Arc<dyn SessionTokens>,
    pub ids: Arc<dyn IdGenerator>,
    pub clock: Arc<dyn Clock>,
}

/// Accounts, sign-in and sessions.
#[derive(Clone)]
pub struct AuthService {
    ports: Arc<AuthPorts>,
    allow_registration: bool,
    per_account: Arc<Throttle>,
    per_address: Arc<Throttle>,
    registrations: Arc<Throttle>,
    /// A real hash of nothing in particular, verified when the username is
    /// unknown so that the answer takes as long as for a wrong password.
    dummy_hash: Arc<OnceLock<String>>,
}

impl AuthService {
    pub fn new(ports: AuthPorts, allow_registration: bool) -> Self {
        Self {
            ports: Arc::new(ports),
            allow_registration,
            per_account: Arc::new(Throttle::new(LockoutPolicy::PER_ACCOUNT)),
            per_address: Arc::new(Throttle::new(LockoutPolicy::PER_ADDRESS)),
            registrations: Arc::new(Throttle::new(LockoutPolicy::REGISTRATIONS)),
            dummy_hash: Arc::default(),
        }
    }

    /// Creates an account and returns a session token. `client` is the
    /// address the request came from, when known.
    pub async fn register(
        &self,
        username: &str,
        password: &str,
        client: Option<IpAddr>,
    ) -> ServerResult<String> {
        if !self.allow_registration {
            return Err(ServerError::RegistrationClosed);
        }
        let now = self.ports.clock.now();
        let address = client.map(address_key);
        if let Some(address) = &address {
            // Every attempt counts, successful or not, including this one.
            limited(self.registrations.check(address, now))?;
            self.registrations.failed(address, now);
            limited(self.registrations.check(address, now))?;
        }
        let username = validate_username(username)?;
        validate_password(password)?;
        let user = User {
            id: self.ports.ids.random(),
            username,
            password_hash: self.ports.hasher.hash(password).await?,
            household_id: None,
        };
        if !self.ports.users.insert(&user).await? {
            return Err(ServerError::Conflict("this username is taken".into()));
        }
        self.open_session(user.id, now).await
    }

    /// Signs in and returns a new session token.
    pub async fn login(
        &self,
        username: &str,
        password: &str,
        client: Option<IpAddr>,
    ) -> ServerResult<String> {
        let now = self.ports.clock.now();
        // The same key for any spelling of the name, valid or not.
        let account = format!("user:{}", username.trim().to_lowercase());
        let address = client.map(address_key);
        // Checked before hashing, so a locked-out attempt costs nothing, and
        // answered the same whether the account exists or not.
        limited(self.per_account.check(&account, now))?;
        if let Some(address) = &address {
            limited(self.per_address.check(address, now))?;
        }

        let user = match validate_username(username) {
            Ok(name) => self.ports.users.find_by_username(&name).await?,
            Err(_) => None,
        };
        let hash = match &user {
            Some(user) => user.password_hash.clone(),
            None => self.dummy_hash().await?,
        };
        let matches = self.ports.hasher.verify(password, &hash).await?;
        match user {
            Some(user) if matches => {
                // Only the account is cleared: signing in to one's own
                // account must not reset the count of an address that is
                // guessing at others.
                self.per_account.succeeded(&account);
                self.open_session(user.id, now).await
            }
            _ => {
                self.per_account.failed(&account, now);
                if let Some(address) = &address {
                    self.per_address.failed(address, now);
                }
                Err(ServerError::BadCredentials)
            }
        }
    }

    /// The user a request's token belongs to.
    pub async fn authenticate(&self, token: &str) -> ServerResult<User> {
        let now = self.ports.clock.now();
        let key = self.ports.tokens.hash(token);
        let session = self
            .ports
            .sessions
            .find(&key)
            .await?
            .ok_or(ServerError::BadToken)?;
        if !session.is_valid(now) {
            self.ports.sessions.delete(&key).await?;
            return Err(ServerError::BadToken);
        }
        if session.needs_touch(now) {
            self.ports.sessions.touch(&key, now).await?;
        }
        // The account may have been removed since.
        self.ports
            .users
            .find_by_id(session.user_id)
            .await?
            .ok_or(ServerError::BadToken)
    }

    /// Ends the session of this token.
    pub async fn logout(&self, token: &str) -> ServerResult<()> {
        self.ports
            .sessions
            .delete(&self.ports.tokens.hash(token))
            .await
    }

    /// Ends every session of the user, on every device.
    pub async fn logout_everywhere(&self, user: &User) -> ServerResult<u64> {
        self.ports.sessions.delete_for_user(user.id).await
    }

    /// Ends every session of the named account. For the server's owner, from
    /// the command line, when a phone is lost.
    pub async fn revoke_sessions(&self, username: &str) -> ServerResult<u64> {
        let username = validate_username(username)?;
        let user = self
            .ports
            .users
            .find_by_username(&username)
            .await?
            .ok_or_else(|| ServerError::NotFound(format!("no account named {username}")))?;
        self.logout_everywhere(&user).await
    }

    /// Deletes expired sessions. Returns how many.
    pub async fn purge_expired_sessions(&self) -> ServerResult<u64> {
        let (idle, created) = expiry_cutoffs(self.ports.clock.now());
        self.ports.sessions.purge(idle, created).await
    }

    async fn open_session(&self, user_id: uuid::Uuid, now: i64) -> ServerResult<String> {
        let token = self.ports.tokens.generate();
        let session = Session {
            user_id,
            created_at: now,
            last_used_at: now,
        };
        self.ports
            .sessions
            .create(&self.ports.tokens.hash(&token), &session)
            .await?;
        Ok(token)
    }

    async fn dummy_hash(&self) -> ServerResult<String> {
        if let Some(hash) = self.dummy_hash.get() {
            return Ok(hash.clone());
        }
        let hash = self
            .ports
            .hasher
            .hash("no account has this password")
            .await?;
        Ok(self.dummy_hash.get_or_init(|| hash).clone())
    }
}

fn address_key(ip: IpAddr) -> String {
    // An IPv4 client of a dual-stack socket shows up as ::ffff:a.b.c.d.
    let ip = ip.to_canonical();
    // IPv6 clients usually own a whole /64: count the prefix, not the
    // address, or rotating within it would escape the limit.
    match ip {
        IpAddr::V4(v4) => format!("ip:{v4}"),
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("ip:{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
    }
}

fn limited(check: Result<(), i64>) -> ServerResult<()> {
    check.map_err(|retry_after_secs| ServerError::TooManyAttempts { retry_after_secs })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Fakes;
    use larder_server_domain::DomainError;
    use larder_server_domain::session::{ABSOLUTE_LIMIT_SECS, IDLE_LIMIT_SECS};

    const HOME: Option<IpAddr> = Some(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 20)));

    #[tokio::test]
    async fn register_then_authenticate() {
        let auth = Fakes::default().auth(true);
        let token = auth.register(" Ana ", "longenough", HOME).await.unwrap();
        let user = auth.authenticate(&token).await.unwrap();
        assert_eq!(user.username, "ana");
        assert_eq!(user.household_id, None);
    }

    #[tokio::test]
    async fn password_and_token_are_stored_hashed() {
        let fakes = Fakes::default();
        let auth = fakes.auth(true);
        let token = auth.register("ana", "longenough", HOME).await.unwrap();
        assert_ne!(fakes.users.all()[0].password_hash, "longenough");
        let stored = fakes.sessions.keys();
        assert_eq!(stored.len(), 1);
        assert_ne!(stored[0], token);
    }

    #[tokio::test]
    async fn register_validates_input() {
        let auth = Fakes::default().auth(true);
        assert_eq!(
            auth.register("a", "longenough", HOME).await.unwrap_err(),
            ServerError::Invalid(DomainError::InvalidUsername)
        );
        assert_eq!(
            auth.register("ana", "short", HOME).await.unwrap_err(),
            ServerError::Invalid(DomainError::WeakPassword)
        );
    }

    #[tokio::test]
    async fn duplicate_username_is_a_conflict_even_with_other_case() {
        let auth = Fakes::default().auth(true);
        auth.register("ana", "longenough", HOME).await.unwrap();
        assert!(matches!(
            auth.register("ANA", "otherpassword", HOME).await,
            Err(ServerError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn closed_registration_refuses_new_accounts() {
        let auth = Fakes::default().auth(false);
        assert_eq!(
            auth.register("ana", "longenough", HOME).await.unwrap_err(),
            ServerError::RegistrationClosed
        );
    }

    #[tokio::test]
    async fn registrations_per_address_are_limited() {
        let auth = Fakes::default().auth(true);
        for i in 0..10 {
            auth.register(&format!("user{i}"), "longenough", HOME)
                .await
                .unwrap();
        }
        assert!(matches!(
            auth.register("user10", "longenough", HOME).await,
            Err(ServerError::TooManyAttempts { .. })
        ));
        let elsewhere = Some("10.0.0.9".parse().unwrap());
        auth.register("user10", "longenough", elsewhere)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn login_with_right_password_works_case_insensitively() {
        let auth = Fakes::default().auth(true);
        auth.register("ana", "longenough", HOME).await.unwrap();
        let token = auth.login("Ana", "longenough", HOME).await.unwrap();
        assert_eq!(auth.authenticate(&token).await.unwrap().username, "ana");
    }

    #[tokio::test]
    async fn each_login_is_its_own_session() {
        let auth = Fakes::default().auth(true);
        let first = auth.register("ana", "longenough", HOME).await.unwrap();
        let second = auth.login("ana", "longenough", HOME).await.unwrap();
        assert_ne!(first, second);
        auth.logout(&first).await.unwrap();
        assert_eq!(
            auth.authenticate(&first).await.unwrap_err(),
            ServerError::BadToken
        );
        assert!(auth.authenticate(&second).await.is_ok());
    }

    #[tokio::test]
    async fn wrong_password_unknown_user_and_invalid_name_look_the_same() {
        let fakes = Fakes::default();
        let auth = fakes.auth(true);
        auth.register("ana", "longenough", HOME).await.unwrap();
        for (user, pass) in [("ana", "wrongpassword"), ("bob", "longenough"), ("!", "x")] {
            let before = fakes.hasher.verifications();
            assert_eq!(
                auth.login(user, pass, HOME).await.unwrap_err(),
                ServerError::BadCredentials
            );
            // A password is checked every time, so the timing is the same.
            assert_eq!(fakes.hasher.verifications(), before + 1, "{user}");
        }
    }

    #[tokio::test]
    async fn repeated_failures_lock_the_account_even_for_the_right_password() {
        let fakes = Fakes::default();
        let auth = fakes.auth(true);
        auth.register("ana", "longenough", HOME).await.unwrap();
        for _ in 0..6 {
            let _ = auth.login("ana", "wrongpassword", HOME).await;
        }
        let before = fakes.hasher.verifications();
        assert_eq!(
            auth.login("ana", "longenough", HOME).await.unwrap_err(),
            ServerError::TooManyAttempts {
                retry_after_secs: 30
            }
        );
        // Refused before hashing.
        assert_eq!(fakes.hasher.verifications(), before);
        fakes.clock.advance(30);
        auth.login("ana", "longenough", HOME).await.unwrap();
    }

    #[tokio::test]
    async fn unknown_accounts_are_locked_the_same_way() {
        let auth = Fakes::default().auth(true);
        for _ in 0..6 {
            let _ = auth.login("ghost", "whatever1", HOME).await;
        }
        assert!(matches!(
            auth.login("ghost", "whatever1", HOME).await,
            Err(ServerError::TooManyAttempts { .. })
        ));
    }

    #[tokio::test]
    async fn one_address_cannot_spray_many_accounts() {
        let auth = Fakes::default().auth(true);
        for i in 0..21 {
            let _ = auth.login(&format!("user{i}"), "password1", HOME).await;
        }
        assert!(matches!(
            auth.login("someone", "password1", HOME).await,
            Err(ServerError::TooManyAttempts { .. })
        ));
    }

    #[tokio::test]
    async fn ipv6_clients_are_counted_per_64_prefix() {
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        assert_eq!(address_key(a), address_key(b));
        let mapped: IpAddr = "::ffff:192.168.1.20".parse().unwrap();
        assert_eq!(address_key(mapped), "ip:192.168.1.20");
    }

    #[tokio::test]
    async fn forged_token_is_rejected() {
        let auth = Fakes::default().auth(true);
        assert_eq!(
            auth.authenticate("not-a-token").await.unwrap_err(),
            ServerError::BadToken
        );
    }

    #[tokio::test]
    async fn token_of_a_removed_account_is_rejected() {
        let fakes = Fakes::default();
        let auth = fakes.auth(true);
        let token = auth.register("ana", "longenough", HOME).await.unwrap();
        fakes.users.clear();
        assert_eq!(
            auth.authenticate(&token).await.unwrap_err(),
            ServerError::BadToken
        );
    }

    #[tokio::test]
    async fn session_expires_when_idle_and_use_keeps_it_alive() {
        let fakes = Fakes::default();
        let auth = fakes.auth(true);
        let token = auth.register("ana", "longenough", HOME).await.unwrap();
        fakes.clock.advance(IDLE_LIMIT_SECS - 10);
        auth.authenticate(&token).await.unwrap();
        fakes.clock.advance(IDLE_LIMIT_SECS - 10);
        auth.authenticate(&token).await.unwrap();
        fakes.clock.advance(IDLE_LIMIT_SECS);
        assert_eq!(
            auth.authenticate(&token).await.unwrap_err(),
            ServerError::BadToken
        );
        assert!(fakes.sessions.keys().is_empty(), "expired session deleted");
    }

    #[tokio::test]
    async fn session_ends_after_a_year_even_if_used() {
        let fakes = Fakes::default();
        let auth = fakes.auth(true);
        let token = auth.register("ana", "longenough", HOME).await.unwrap();
        let step = IDLE_LIMIT_SECS / 2;
        let mut elapsed = 0;
        while elapsed + step < ABSOLUTE_LIMIT_SECS {
            fakes.clock.advance(step);
            elapsed += step;
            auth.authenticate(&token).await.unwrap();
        }
        fakes.clock.advance(ABSOLUTE_LIMIT_SECS - elapsed);
        assert!(auth.authenticate(&token).await.is_err());
    }

    #[tokio::test]
    async fn logout_everywhere_and_revoke_end_all_sessions() {
        let fakes = Fakes::default();
        let auth = fakes.auth(true);
        let phone = auth.register("ana", "longenough", HOME).await.unwrap();
        let laptop = auth.login("ana", "longenough", HOME).await.unwrap();
        let bob = auth.register("bob", "longenough", HOME).await.unwrap();
        let ana = auth.authenticate(&phone).await.unwrap();
        assert_eq!(auth.logout_everywhere(&ana).await.unwrap(), 2);
        assert!(auth.authenticate(&laptop).await.is_err());
        assert!(auth.authenticate(&bob).await.is_ok());

        assert_eq!(auth.revoke_sessions("BOB").await.unwrap(), 1);
        assert!(auth.authenticate(&bob).await.is_err());
        assert!(matches!(
            auth.revoke_sessions("nobody").await,
            Err(ServerError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn purge_removes_only_expired_sessions() {
        let fakes = Fakes::default();
        let auth = fakes.auth(true);
        auth.register("ana", "longenough", HOME).await.unwrap();
        fakes.clock.advance(IDLE_LIMIT_SECS);
        let fresh = auth.login("ana", "longenough", HOME).await.unwrap();
        assert_eq!(auth.purge_expired_sessions().await.unwrap(), 1);
        assert!(auth.authenticate(&fresh).await.is_ok());
    }
}
