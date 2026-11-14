use larder_server_domain::DomainError;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ServerError {
    #[error("{0}")]
    Invalid(#[from] DomainError),
    /// Deliberately vague: never says whether the username exists.
    #[error("wrong username or password")]
    BadCredentials,
    #[error("sign in again")]
    BadToken,
    #[error("too many attempts, try again in {} minute(s)", (retry_after_secs + 59) / 60)]
    TooManyAttempts { retry_after_secs: i64 },
    #[error("registration is closed on this server")]
    RegistrationClosed,
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    NotFound(String),
    #[error("create or join a household first")]
    NoHousehold,
    #[error("internal error")]
    Internal(String),
}

pub type ServerResult<T> = Result<T, ServerError>;
