//! Files integration tests: presigned URL endpoint.

use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};

use crate::helpers::*;

/// GET /v1/files/{key}/url returns 401 without token (storage is None in TestApp).
#[tokio::test]
async fn test_files_presigned_url_no_token() {
    let app = TestApp::new().await;

    let req = Request::builder()
        .method(Method::GET)
        .uri("/v1/files/some-key/url")
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// GET /v1/files/{key}/url returns 401 with invalid token.
#[tokio::test]
async fn test_files_presigned_url_invalid_token() {
    let app = TestApp::new().await;

    let resp = app
        .get_with_bearer("/v1/files/some-key/url", "invalid.jwt.token")
        .await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// GET /v1/files/{key}/url returns 500 when storage not configured (valid token).
#[tokio::test]
async fn test_files_presigned_url_storage_not_configured() {
    let app = TestApp::new().await;

    let token = app
        .get_token_via_register("files@example.com", "secret123")
        .await;
    let Some(tok) = token else {
        return; // Auth not configured
    };

    let resp = app.get_with_bearer("/v1/files/some-key/url", &tok).await;

    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
