use std::sync::Arc;
use std::time::Duration;

use larder_server::config::Config;
use larder_server::{AppState, router, tls};
use larder_server_infrastructure::{Argon2Hasher, Db, display_fingerprint};

const USAGE: &str = "usage:
  larder-server                            run the server
  larder-server fingerprint                print the certificate fingerprint
  larder-server revoke-sessions <username> sign that account out of every device
  larder-server reset-certificate          make a new certificate on next start
                                           (every phone must then sign in again)";

#[tokio::main]
async fn main() {
    if let Err(message) = run().await {
        eprintln!("larder-server: {message}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let config = Config::from_env()?;
    let db = Db::open(&config.database)
        .await
        .map_err(|e| format!("cannot open database {}: {e:?}", config.database))?;
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        [] => serve(config, db).await,
        ["fingerprint"] => {
            println!("{}", fingerprint(&db).await?);
            Ok(())
        }
        ["revoke-sessions", username] => {
            let state = AppState::new(db, Arc::new(Argon2Hasher::new()), false);
            let count = state
                .auth
                .revoke_sessions(username)
                .await
                .map_err(|e| e.to_string())?;
            println!("{username} signed out of {count} device(s)");
            Ok(())
        }
        ["reset-certificate"] => {
            db.reset_tls_identity()
                .await
                .map_err(|e| format!("{e:?}"))?;
            println!("a new certificate will be made on the next start");
            Ok(())
        }
        ["help" | "--help" | "-h"] => {
            println!("{USAGE}");
            Ok(())
        }
        _ => Err(format!("unknown command\n{USAGE}")),
    }
}

async fn fingerprint(db: &Db) -> Result<String, String> {
    let identity = db.tls_identity().await.map_err(|e| format!("{e:?}"))?;
    let hex = identity.fingerprint().map_err(|e| format!("{e:?}"))?;
    Ok(display_fingerprint(&hex))
}

async fn serve(config: Config, db: Db) -> Result<(), String> {
    let identity = db
        .tls_identity()
        .await
        .map_err(|e| format!("cannot load the TLS certificate: {e:?}"))?;
    let fingerprint = fingerprint(&db).await?;
    let state = AppState::new(db, Arc::new(Argon2Hasher::new()), config.allow_registration);
    purge_sessions_hourly(state.clone());
    let listener = std::net::TcpListener::bind(&config.bind)
        .map_err(|e| format!("cannot listen on {}: {e}", config.bind))?;
    println!(
        "larder-server {} listening on https://{} (database: {}, registration {})",
        env!("CARGO_PKG_VERSION"),
        config.bind,
        config.database,
        if config.allow_registration {
            "open"
        } else {
            "closed"
        },
    );
    println!("certificate fingerprint (SHA-256): {fingerprint}");
    tls::serve(listener, &identity, router(state), shutdown_signal()).await?;
    println!("larder-server stopped");
    Ok(())
}

/// Expired sessions are refused anyway; this only keeps the table small.
fn purge_sessions_hourly(state: AppState) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60 * 60));
        loop {
            tick.tick().await;
            if let Err(e) = state.auth.purge_expired_sessions().await {
                eprintln!("cannot purge expired sessions: {e:?}");
            }
        }
    });
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
