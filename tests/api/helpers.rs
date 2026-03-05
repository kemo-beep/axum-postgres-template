use axum::{body::Body, http::Request, http::Response, Router};
use sqlx::{Connection, Executor, PgConnection};
use std::sync::Once;
use tower::ServiceExt;
use uuid::Uuid;

use server::{router, telemetry, Configuration, Db};

static TRACING: Once = Once::new();

pub struct TestApp {
    pub router: Router,
    pub db: Db,
}

impl TestApp {
    pub async fn new() -> Self {
        // Loads the .env file located in the environment's current directory or its parents in sequence.
        // .env used only for development, so we discard error in all other cases.
        dotenvy::dotenv().ok();

        // Set port to 0 so tests can spawn multiple servers on OS assigned ports.
        std::env::set_var("PORT", "0");

        // Setup tracing. Once.
        TRACING.call_once(telemetry::setup_tracing);

        // Parse configuration from the environment.
        // This will exit with a help message if something is wrong.
        let cfg = Configuration::new();

        // Creates db with a random name for tests.
        let db_dsn = create_test_db(&cfg.db_dsn).await;
        // Initialize test db pool.
        let db = Db::new(&db_dsn, cfg.db_pool_max_size)
            .await
            .expect("Failed to initialize db");

        tracing::debug!("Running migrations");
        db.migrate().await.expect("Failed to run migrations");

        let router = router(cfg, db.clone(), None);
        Self { db, router }
    }

    pub async fn request(&self, req: Request<Body>) -> Response<Body> {
        self.router.clone().oneshot(req).await.unwrap()
    }
}

/// Creates db with a random name for tests.
pub async fn create_test_db(db_dsn: &str) -> String {
    // Parse DSN: postgres://user:pass@host:port/dbname -> replace dbname with random
    let (base, _db) = db_dsn
        .rsplit_once('/')
        .expect("DATABASE_URL must contain database name (e.g. postgres://host/dbname)");
    let randon_db_name = Uuid::now_v7().to_string();
    let db_url = format!("{}/{}", base, randon_db_name);
    let admin_url = format!("{}/postgres", base);
    let mut conn = PgConnection::connect(&admin_url)
        .await
        .expect("Failed to connect to Postgres");
    conn.execute(format!(r#"CREATE DATABASE "{}";"#, randon_db_name).as_str())
        .await
        .expect("Failed to create test database");
    db_url
}
