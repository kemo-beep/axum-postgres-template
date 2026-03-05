use server::{telemetry, Configuration, Db};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    // Loads the .env file located in the environment's current directory or its parents in sequence.
    // .env used only for development, so we discard error in all other cases.
    dotenvy::dotenv().ok();

    // Tries to load tracing config from environment (RUST_LOG) or uses "debug".
    telemetry::setup_tracing();

    // Parse configuration from the environment.
    // This will exit with a help message if something is wrong.
    tracing::debug!("Initializing configuration");
    let cfg = Configuration::new();

    // Initialize db pool.
    tracing::debug!("Initializing db pool");
    let db = Db::new(&cfg.db_dsn, cfg.db_pool_max_size)
        .await
        .expect("Failed to initialize db");

    tracing::debug!("Running migrations");
    db.migrate().await.expect("Failed to run migrations");

    // Spin up our server.
    tracing::info!("Starting server on {}", cfg.listen_address);
    let listener = TcpListener::bind(&cfg.listen_address)
        .await
        .expect("Failed to bind address");

    let storage_service = match &cfg.r2 {
        Some(r2) => match server::storage::StorageService::from_config(r2).await {
            Ok(s) => {
                tracing::info!("R2 storage configured");
                Some(s)
            }
            Err(e) => {
                tracing::debug!("R2 storage not available: {} (add aws-sdk-s3 for full support)", e);
                None
            }
        },
        None => None,
    };

    let router = server::router(cfg, db, storage_service);

    // Use connect_info for rate limiting (tower_governor PeerIpKeyExtractor)
    axum::serve(listener, router.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("Failed to start server");

    tracing::info!("Server shut down");
}

/// Returns a future that completes when SIGTERM or SIGINT is received.
async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install Ctrl+C handler");
}
