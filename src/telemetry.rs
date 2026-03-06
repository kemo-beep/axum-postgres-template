use axum::body::Body;
use axum::http::Response;
use std::time::Duration;
use tower_http::{
    classify::{ServerErrorsAsFailures, SharedClassifier},
    trace::{DefaultMakeSpan, DefaultOnRequest, TraceLayer},
};
use tracing::{Span, Level};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Callback that colorizes logs by HTTP status and includes method, uri, status, latency.
/// Method and uri come from the parent span (DefaultMakeSpan); a divider separates request blocks.
/// Note: Response body is not logged—doing so would require buffering the stream and custom middleware.
fn on_response_colorized(
    response: &Response<Body>,
    latency: Duration,
    _span: &Span,
) {
    let status = response.status().as_u16();
    let latency_ms = latency.as_millis();
    let level = if status >= 500 {
        Level::ERROR
    } else if status >= 400 {
        Level::WARN
    } else {
        Level::INFO
    };
    match level {
        Level::ERROR => {
            tracing::error!(%latency_ms, status = status, "finished processing request");
        }
        Level::WARN => {
            tracing::warn!(%latency_ms, status = status, "finished processing request");
        }
        _ => {
            tracing::info!(%latency_ms, status = status, "finished processing request");
        }
    }
    // Visual divider between request blocks
    tracing::info!("─────────────────────────────────────────");
}

/// The `EnvFilter` type is used to filter log events based on the value of an environment variable.
/// In this case, we are using the `try_from_default_env` method to attempt to read the `RUST_LOG` environment variable,
/// which is used to set the log level for the application.
/// If the environment variable is not set, we default to the log level of `debug`.
/// The `RUST_LOG` environment variable is set in the Dockerfile and .env files.
pub fn setup_tracing() {
    let env_filter_layer = EnvFilter::try_from_default_env().unwrap_or_else(|_| "debug".into());
    let is_production = std::env::var("APP_ENVIRONMENT").as_deref() == Ok("production");
    if is_production {
        tracing_subscriber::registry()
            .with(env_filter_layer)
            .with(fmt::layer().json())
            .init();
    } else {
        // Compact: single-line, consistent columns; method/uri from span; divider between requests
        tracing_subscriber::registry()
            .with(env_filter_layer)
            .with(
                fmt::layer()
                    .with_ansi(true)
                    .with_target(false)
                    .event_format(fmt::format().compact()),
            )
            .init();
    }
}

/// Returns a `TraceLayer` for HTTP requests and responses.
/// The `TraceLayer` is used to trace requests and responses in the application.
#[allow(clippy::type_complexity)]
pub fn trace_layer(
) -> TraceLayer<
    SharedClassifier<ServerErrorsAsFailures>,
    DefaultMakeSpan,
    tower_http::trace::DefaultOnRequest,
    fn(&axum::http::Response<axum::body::Body>, Duration, &Span),
    tower_http::trace::DefaultOnBodyChunk,
    tower_http::trace::DefaultOnEos,
    tower_http::trace::DefaultOnFailure,
> {
    TraceLayer::new_for_http()
        .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
        .on_request(DefaultOnRequest::new().level(Level::DEBUG))
        .on_response(on_response_colorized)
}
