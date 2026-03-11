use std::time::Duration;

use axum::{
    extract::Request,
    http::{HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use hyper::Method;
use serde::Serialize;
use tower_http::{
    cors::{AllowHeaders, AllowOrigin, Any, CorsLayer},
    limit::RequestBodyLimitLayer,
    normalize_path::NormalizePathLayer,
    request_id::{MakeRequestId, PropagateRequestIdLayer, RequestId, SetRequestIdLayer},
    set_header::SetResponseHeaderLayer,
    timeout::TimeoutLayer,
};

/// Layer for X-Content-Type-Options: nosniff.
pub fn x_content_type_options_layer() -> SetResponseHeaderLayer<HeaderValue> {
    SetResponseHeaderLayer::if_not_present(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    )
}

/// Layer for X-Frame-Options: DENY.
pub fn x_frame_options_layer() -> SetResponseHeaderLayer<HeaderValue> {
    SetResponseHeaderLayer::if_not_present(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    )
}

/// Layer for Strict-Transport-Security (HSTS). Use in production only.
pub fn hsts_layer() -> SetResponseHeaderLayer<HeaderValue> {
    SetResponseHeaderLayer::if_not_present(
        HeaderName::from_static("strict-transport-security"),
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    )
}

#[derive(Clone, Default)]
pub struct Id;

impl MakeRequestId for Id {
    fn make_request_id<B>(&mut self, _: &Request<B>) -> Option<RequestId> {
        let id = uuid::Uuid::now_v7().to_string().parse().unwrap();
        Some(RequestId::new(id))
    }
}

/// Sets the 'x-request-id' header with a randomly generated UUID v7.
///
/// SetRequestId will not override request IDs if they are already present
/// on requests or responses.
pub fn request_id_layer() -> SetRequestIdLayer<Id> {
    let x_request_id = HeaderName::from_static("x-request-id");
    SetRequestIdLayer::new(x_request_id.clone(), Id)
}

// Propagates 'x-request-id' header from the request to the response.
///
/// PropagateRequestId wont override request ids if its already
/// present on requests or responses.
pub fn propagate_request_id_layer() -> PropagateRequestIdLayer {
    let x_request_id = HeaderName::from_static("x-request-id");
    PropagateRequestIdLayer::new(x_request_id)
}

/// Layer that applies the Cors middleware which adds headers for CORS.
/// If origins is empty or contains "*", allows any origin. Otherwise allows the listed origins.
pub fn cors_layer(origins: &[String]) -> CorsLayer {
    let allow_origin = if origins.is_empty() || origins.iter().any(|o| o == "*") {
        AllowOrigin::any()
    } else {
        let values: Vec<HeaderValue> = origins
            .iter()
            .filter_map(|s| HeaderValue::try_from(s.as_str()).ok())
            .collect();
        if values.is_empty() {
            AllowOrigin::any()
        } else {
            AllowOrigin::list(values)
        }
    };
    CorsLayer::new()
        .allow_origin(allow_origin)
        .allow_methods(Any)
        .allow_headers(AllowHeaders::mirror_request())
        .max_age(Duration::from_secs(600))
}

/// Layer that applies the Timeout middleware which apply a timeout to requests.
/// The default timeout value is set to 15 seconds.
pub fn timeout_layer() -> TimeoutLayer {
    TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, Duration::from_secs(15))
}

/// Middleware that normalizes paths.
///
/// Any trailing slashes from request paths will be removed. For example, a request with `/foo/`
/// will be changed to `/foo` before reaching the inner service.
pub fn normalize_path_layer() -> NormalizePathLayer {
    NormalizePathLayer::trim_trailing_slash()
}

/// Request body size limit in bytes (1 MiB). Applied to all JSON/body-consuming routes.
pub const REQUEST_BODY_LIMIT: usize = 1 << 20;

/// Layer that limits request body size. Returns 413 Payload Too Large when exceeded.
pub fn request_body_limit_layer() -> RequestBodyLimitLayer {
    RequestBodyLimitLayer::new(REQUEST_BODY_LIMIT)
}

/// Idempotency-Key header name.
pub const IDEMPOTENCY_KEY: HeaderName = HeaderName::from_static("idempotency-key");

/// Require Idempotency-Key header on mutable methods (POST, PUT, PATCH, DELETE).
/// Returns 400 if missing or invalid (must be valid UUID).
pub async fn require_idempotency_key(request: Request, next: axum::middleware::Next) -> Response {
    let method = request.method().clone();
    if !method.is_mutable() {
        return next.run(request).await;
    }
    let key = request
        .headers()
        .get(&IDEMPOTENCY_KEY)
        .and_then(|v| v.to_str().ok());
    let Some(key) = key else {
        return (
            StatusCode::BAD_REQUEST,
            Json(IdempotencyError {
                message: "Missing Idempotency-Key header (required for POST, PUT, PATCH, DELETE)".into(),
            }),
        )
            .into_response();
    };
    if uuid::Uuid::parse_str(key.trim()).is_err() {
        return (
            StatusCode::BAD_REQUEST,
            Json(IdempotencyError {
                message: "Idempotency-Key must be a valid UUID".into(),
            }),
        )
            .into_response();
    }
    next.run(request).await
}

#[derive(Serialize)]
struct IdempotencyError {
    message: String,
}

trait MethodExt {
    fn is_mutable(&self) -> bool;
}
impl MethodExt for Method {
    fn is_mutable(&self) -> bool {
        self == Method::POST || self == Method::PUT || self == Method::PATCH || self == Method::DELETE
    }
}

/// Layer that adds `Deprecation: true` header. Use for endpoints being retired.
/// For Sunset date, add `.layer(SetResponseHeaderLayer::overriding(...))` with `sunset` header.
pub fn deprecation_layer() -> SetResponseHeaderLayer<HeaderValue> {
    SetResponseHeaderLayer::overriding(
        HeaderName::from_static("deprecation"),
        HeaderValue::from_static("true"),
    )
}

/// Layer that adds `Sunset` header (RFC 8594). Use with deprecation_layer for retiring endpoints.
/// Format: `Sat, 01 Jan 2027 00:00:00 GMT`
pub fn sunset_layer(sunset_date: &'static str) -> SetResponseHeaderLayer<HeaderValue> {
    SetResponseHeaderLayer::overriding(
        HeaderName::from_static("sunset"),
        HeaderValue::try_from(sunset_date).unwrap_or(HeaderValue::from_static("")),
    )
}
