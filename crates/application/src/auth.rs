use std::sync::Arc;

use larder_server_domain::{User, validate_password, validate_username};

use crate::error::{ServerError, ServerResult};
use crate::ports::{IdGenerator, PasswordHasher, TokenService, UserRepository};

#[derive(Clone)]
pub struct AuthService {
    users: Arc<dyn UserRepository>,
    hasher: Arc<dyn PasswordHasher>,
    tokens: Arc<dyn TokenService>,
    ids: Arc<dyn IdGenerator>,
    allow_registration: bool,
}

impl AuthService {
    pub fn new(
        users: Arc<dyn UserRepository>,
        hasher: Arc<dyn PasswordHasher>,
        tokens: Arc<dyn TokenService>,
        ids: Arc<dyn IdGenerator>,
        allow_registration: bool,
    ) -> Self {
        Self {
            users,
            hasher,
            tokens,
            ids,
            allow_registration,
        }
    }

    /// Creates an account and returns an access token.
    pub async fn register(&self, username: &str, password: &str) -> ServerResult<String> {
        if !self.allow_registration {
            return Err(ServerError::RegistrationClosed);
        }
        let username = validate_username(username)?;
        validate_password(password)?;
        let user = User {
            id: self.ids.random(),
            username,
            password_hash: self.hasher.hash(password).await?,
            household_id: None,
        };
        if !self.users.insert(&user).await? {
            return Err(ServerError::Conflict("this username is taken".into()));
        }
        self.tokens.issue(user.id)
    }

    pub async fn login(&self, username: &str, password: &str) -> ServerResult<String> {
        // An invalid username cannot exist; answer exactly like a wrong
        // password.
        let Ok(username) = validate_username(username) else {
            return Err(ServerError::BadCredentials);
        };
        let Some(user) = self.users.find_by_username(&username).await? else {
            return Err(ServerError::BadCredentials);
        };
        if !self.hasher.verify(password, &user.password_hash).await? {
            return Err(ServerError::BadCredentials);
        }
        self.tokens.issue(user.id)
    }

    /// The user a request's token belongs to.
    pub async fn authenticate(&self, token: &str) -> ServerResult<User> {
        let id = self.tokens.verify(token).ok_or(ServerError::BadToken)?;
        // The account may have been removed since the token was issued.
        self.users
            .find_by_id(id)
            .await?
            .ok_or(ServerError::BadToken)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Fakes;
    use larder_server_domain::DomainError;

    #[tokio::test]
    async fn register_then_authenticate() {
        let auth = Fakes::default().auth(true);
        let token = auth.register(" Ana ", "longenough").await.unwrap();
        let user = auth.authenticate(&token).await.unwrap();
        assert_eq!(user.username, "ana");
        assert_eq!(user.household_id, None);
    }

    #[tokio::test]
    async fn password_is_stored_hashed() {
        let fakes = Fakes::default();
        let auth = fakes.auth(true);
        auth.register("ana", "longenough").await.unwrap();
        let stored = fakes.users.all()[0].password_hash.clone();
        assert_ne!(stored, "longenough");
    }

    #[tokio::test]
    async fn register_validates_input() {
        let auth = Fakes::default().auth(true);
        assert_eq!(
            auth.register("a", "longenough").await.unwrap_err(),
            ServerError::Invalid(DomainError::InvalidUsername)
        );
        assert_eq!(
            auth.register("ana", "short").await.unwrap_err(),
            ServerError::Invalid(DomainError::WeakPassword)
        );
    }

    #[tokio::test]
    async fn duplicate_username_is_a_conflict_even_with_other_case() {
        let auth = Fakes::default().auth(true);
        auth.register("ana", "longenough").await.unwrap();
        assert!(matches!(
            auth.register("ANA", "otherpassword").await,
            Err(ServerError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn closed_registration_refuses_new_accounts() {
        let auth = Fakes::default().auth(false);
        assert_eq!(
            auth.register("ana", "longenough").await.unwrap_err(),
            ServerError::RegistrationClosed
        );
    }

    #[tokio::test]
    async fn login_with_right_password_works_case_insensitively() {
        let auth = Fakes::default().auth(true);
        auth.register("ana", "longenough").await.unwrap();
        let token = auth.login("Ana", "longenough").await.unwrap();
        assert_eq!(auth.authenticate(&token).await.unwrap().username, "ana");
    }

    #[tokio::test]
    async fn wrong_password_unknown_user_and_invalid_name_look_the_same() {
        let auth = Fakes::default().auth(true);
        auth.register("ana", "longenough").await.unwrap();
        for (user, pass) in [("ana", "wrongpassword"), ("bob", "longenough"), ("!", "x")] {
            assert_eq!(
                auth.login(user, pass).await.unwrap_err(),
                ServerError::BadCredentials
            );
        }
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
        let token = auth.register("ana", "longenough").await.unwrap();
        fakes.users.clear();
        assert_eq!(
            auth.authenticate(&token).await.unwrap_err(),
            ServerError::BadToken
        );
    }
}
