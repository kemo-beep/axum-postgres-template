use std::time::Duration;

use axum::http::{HeaderName, HeaderValue, StatusCode};
use hyper::Request;
use tower_http::{
    cors::{AllowHeaders, AllowOrigin, Any, CorsLayer},
    normalize_path::NormalizePathLayer,
    request_id::{MakeRequestId, PropagateRequestIdLayer, RequestId, SetRequestIdLayer},
    set_header::SetResponseHeaderLayer,
    timeout::TimeoutLayer,
};

/// Layer for X-Content-Type-Options: nosniff.
pub fn x_content_type_options_layer(
) -> SetResponseHeaderLayer<HeaderValue> {
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
