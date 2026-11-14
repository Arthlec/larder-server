//! HTTP interface of the Larder server and its composition root.

pub mod config;
mod routes;

use std::sync::Arc;
use std::time::Duration;

use larder_server_application::ports::PasswordHasher;
use larder_server_application::{AuthService, HouseholdService, ServerResult, SyncService};
use larder_server_infrastructure::{Db, JwtTokens, RandomIds};

pub use routes::router;

/// How long a sign-in lasts. Long, because this is a home server and typing
/// a password on a phone every week would only push people to weak ones.
const TOKEN_LIFETIME: Duration = Duration::from_secs(180 * 24 * 60 * 60);

/// The use cases, wired to their adapters.
#[derive(Clone)]
pub struct AppState {
    pub auth: AuthService,
    pub households: HouseholdService,
    pub sync: SyncService,
}

impl AppState {
    pub async fn new(
        db: Db,
        hasher: Arc<dyn PasswordHasher>,
        allow_registration: bool,
    ) -> ServerResult<Self> {
        let db = Arc::new(db);
        let ids = Arc::new(RandomIds);
        let tokens = Arc::new(JwtTokens::new(&db.signing_secret().await?, TOKEN_LIFETIME));
        Ok(Self {
            auth: AuthService::new(db.clone(), hasher, tokens, ids.clone(), allow_registration),
            households: HouseholdService::new(db.clone(), db.clone(), ids),
            sync: SyncService::new(db),
        })
    }
}
