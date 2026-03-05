use axum::{
    body::Body,
    http::{Request, StatusCode},
};

use crate::helpers::*;

#[tokio::test]
async fn test_health_check_ok() {
    let app = TestApp::new().await;

    let req = Request::get("/health").body(Body::empty()).unwrap();
    let resp = app.request(req).await;
    let headers = resp.headers().clone();

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(headers.get("x-request-id").is_some());
    assert_eq!(headers.get("access-control-allow-origin").unwrap(), "*");
    assert!(headers.get("vary").is_some());

    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body.get("status").and_then(|v| v.as_str()), Some("ok"));
}

#[tokio::test]
async fn test_db_connection_ok() {
    let app = TestApp::new().await;
    assert_eq!(app.db.pool.size(), 1);
}
