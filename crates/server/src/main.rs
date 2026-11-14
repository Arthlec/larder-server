use std::sync::Arc;

use larder_server::config::Config;
use larder_server::{AppState, router};
use larder_server_infrastructure::{Argon2Hasher, Db};

#[tokio::main]
async fn main() {
    if let Err(message) = run().await {
        eprintln!("larder-server: {message}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let config = Config::from_env()?;
    let db = Db::open(&config.database)
        .await
        .map_err(|e| format!("cannot open database {}: {e:?}", config.database))?;
    let state = AppState::new(db, Arc::new(Argon2Hasher::new()), config.allow_registration)
        .await
        .map_err(|e| format!("cannot start: {e:?}"))?;
    let listener = tokio::net::TcpListener::bind(&config.bind)
        .await
        .map_err(|e| format!("cannot listen on {}: {e}", config.bind))?;
    println!(
        "larder-server {} listening on http://{} (database: {}, registration {})",
        env!("CARGO_PKG_VERSION"),
        config.bind,
        config.database,
        if config.allow_registration {
            "open"
        } else {
            "closed"
        },
    );
    axum::serve(listener, router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .map_err(|e| format!("server stopped: {e}"))
}
