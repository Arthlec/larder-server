//! HTTP interface of the Larder server and its composition root.

pub mod config;
mod routes;
pub mod tls;

use std::sync::Arc;

use larder_server_application::ports::PasswordHasher;
use larder_server_application::{AuthPorts, AuthService, HouseholdService, SyncService};
use larder_server_infrastructure::{Db, RandomIds, RandomTokens, SystemClock};

pub use routes::router;

/// The use cases, wired to their adapters.
#[derive(Clone)]
pub struct AppState {
    pub auth: AuthService,
    pub households: HouseholdService,
    pub sync: SyncService,
}

impl AppState {
    pub fn new(db: Db, hasher: Arc<dyn PasswordHasher>, allow_registration: bool) -> Self {
        let db = Arc::new(db);
        let ids = Arc::new(RandomIds);
        let auth = AuthService::new(
            AuthPorts {
                users: db.clone(),
                sessions: db.clone(),
                hasher,
                tokens: Arc::new(RandomTokens),
                ids: ids.clone(),
                clock: Arc::new(SystemClock),
            },
            allow_registration,
        );
        Self {
            auth,
            households: HouseholdService::new(db.clone(), db.clone(), ids),
            sync: SyncService::new(db),
        }
    }
}
