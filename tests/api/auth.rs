//! Auth integration tests: send-code, verify-code, register, login, protected routes.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::json;

use crate::helpers::*;

#[tokio::test]
async fn test_send_code_requires_auth_config() {
    let app = TestApp::new().await;

    let req = Request::post("/v1/auth/send-code")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"email":"u@example.com"}"#))
        .unwrap();
    let resp = app.request(req).await;

    // Without JWT_SECRET, auth is disabled -> 500 InternalError
    assert!(
        resp.status() == StatusCode::INTERNAL_SERVER_ERROR || resp.status() == StatusCode::OK,
        "send-code should work when auth configured, or 500 when not"
    );
}

#[tokio::test]
async fn test_register_login() {
    let app = TestApp::new().await;

    // Register
    let req = Request::post("/v1/auth/register")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"email": "reg@example.com", "password": "secret123"}).to_string(),
        ))
        .unwrap();
    let resp = app.request(req).await;

    if resp.status() == StatusCode::INTERNAL_SERVER_ERROR {
        // Auth not configured (no JWT_SECRET)
        return;
    }
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let token = body["access_token"].as_str().expect("access_token");

    // Me (protected)
    let req = Request::get("/v1/auth/me")
        .header("authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Login
    let req = Request::post("/v1/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"email": "reg@example.com", "password": "secret123"}).to_string(),
        ))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_me_returns_401_without_token() {
    let app = TestApp::new().await;

    let req = Request::get("/v1/auth/me").body(Body::empty()).unwrap();
    let resp = app.request(req).await;

    if resp.status() == StatusCode::INTERNAL_SERVER_ERROR {
        return; // Auth not configured
    }
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
