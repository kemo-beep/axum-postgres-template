use axum::{
    body::Body,
    http::{Method, Request, Response, StatusCode},
    Router,
};
use serde_json::Value;
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
    /// POST with JSON body and Content-Type: application/json.
    pub async fn post_json(&self, path: &str, body: Value) -> Response<Body> {
        let req = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        self.request(req).await
    }

    /// GET with Authorization: Bearer {token}.
    pub async fn get_with_bearer(&self, path: &str, token: &str) -> Response<Body> {
        let req = Request::builder()
            .method(Method::GET)
            .uri(path)
            .header("authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();
        self.request(req).await
    }

    /// POST with Authorization: Bearer {token} and optional JSON body.
    pub async fn post_with_bearer(
        &self,
        path: &str,
        token: &str,
        body: Option<Value>,
    ) -> Response<Body> {
        let (body, content_type) = match body {
            Some(b) => (Body::from(b.to_string()), Some("application/json")),
            None => (Body::empty(), None),
        };
        let mut req = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header("authorization", format!("Bearer {}", token));
        if let Some(ct) = content_type {
            req = req.header("content-type", ct);
        }
        let req = req.body(body).unwrap();
        self.request(req).await
    }

    /// Register and return access_token, or None if auth not configured.
    pub async fn get_token_via_register(&self, email: &str, password: &str) -> Option<String> {
        let resp = self
            .post_json(
                "/v1/auth/register",
                serde_json::json!({ "email": email, "password": password }),
            )
            .await;
        if resp.status() == StatusCode::INTERNAL_SERVER_ERROR {
            return None;
        }
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .ok()?;
        let body: Value = serde_json::from_slice(&bytes).ok()?;
        body.get("access_token")
            .and_then(|v| v.as_str())
            .map(String::from)
    }

    /// Login and return access_token, or None if auth not configured.
    pub async fn get_token_via_login(&self, email: &str, password: &str) -> Option<String> {
        let resp = self
            .post_json(
                "/v1/auth/login",
                serde_json::json!({ "email": email, "password": password }),
            )
            .await;
        if resp.status() == StatusCode::INTERNAL_SERVER_ERROR {
            return None;
        }
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .ok()?;
        let body: Value = serde_json::from_slice(&bytes).ok()?;
        body.get("access_token")
            .and_then(|v| v.as_str())
            .map(String::from)
    }

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
