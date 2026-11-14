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
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| format!("server stopped: {e}"))?;
    println!("larder-server stopped");
    Ok(())
}

/// Ctrl-C, or SIGTERM as sent by `podman stop`, `docker stop` and systemd.
/// In a container the server is process 1, which the kernel does not stop on
/// SIGTERM unless the program handles it.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                sigterm.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}
