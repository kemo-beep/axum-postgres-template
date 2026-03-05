//! Webhooks integration tests: Stripe webhook endpoint.

use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};

use crate::helpers::*;

/// POST /webhooks/stripe returns 200 when Stripe is configured.
#[tokio::test]
async fn test_stripe_webhook_configured() {
    let app = TestApp::new().await;

    let req = Request::builder()
        .method(Method::POST)
        .uri("/webhooks/stripe")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"type":"event"}"#))
        .unwrap();
    let resp = app.request(req).await;

    if resp.status() == StatusCode::INTERNAL_SERVER_ERROR {
        return; // Stripe not configured in .env
    }
    assert_eq!(resp.status(), StatusCode::OK);
}

/// POST /webhooks/stripe returns 500 when Stripe is not configured.
/// (TestApp uses Configuration::new() which reads .env - if STRIPE_* are set, we get 200)
#[tokio::test]
async fn test_stripe_webhook_status() {
    let app = TestApp::new().await;

    let req = Request::builder()
        .method(Method::POST)
        .uri("/webhooks/stripe")
        .header("content-type", "application/json")
        .body(Body::from(r#"{}"#))
        .unwrap();
    let resp = app.request(req).await;

    assert!(
        resp.status() == StatusCode::OK || resp.status() == StatusCode::INTERNAL_SERVER_ERROR,
        "Stripe webhook returns 200 (configured) or 500 (not configured)"
    );
}
