use axum::Router;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

pub mod api_error;
pub mod auth;
pub mod billing;
pub mod cfg;
pub mod services;
pub mod db;
pub mod middleware;
pub mod routes;
pub mod storage;
pub mod telemetry;
pub mod types;

pub use cfg::*;
pub use db::*;

#[derive(OpenApi)]
#[openapi(
    paths(
        routes::health_check::health_check,
        auth::routes::send_code,
        auth::routes::verify_code,
        auth::routes::register,
        auth::routes::login,
        auth::routes::google_redirect,
        auth::routes::google_callback,
        auth::routes::me,
        storage::routes::get_presigned_url,
        billing::routes::stripe_webhook,
    ),
    components(
        schemas(
            api_error::ApiErrorResp,
            auth::routes::SendCodeRequest,
            auth::routes::VerifyCodeRequest,
            auth::routes::RegisterRequest,
            auth::routes::LoginRequest,
            auth::routes::AuthResponse,
            auth::routes::UserResponse,
            storage::routes::PresignedUrlResponse,
        )
    ),
    modifiers(&SecurityAddon)
)]
struct ApiDoc;

struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
            components.security_schemes.insert(
                "bearer_auth".into(),
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .build(),
                ),
            );
        }
    }
}

use crate::auth::service::AuthService;
use crate::storage::StorageService;

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub cfg: Config,
    pub auth_service: Option<AuthService>,
    pub storage_service: Option<StorageService>,
}

pub fn router(cfg: Config, db: Db, storage_service: Option<StorageService>) -> Router {
    let auth_service = cfg.jwt_secret.as_ref().map(|_| {
        use crate::auth::repository::{EmailCodeRepository, RbacRepository, UserRepository};
        use crate::auth::{ConsoleEmailSender, EmailSender};
        use std::sync::Arc;

        let user_repo = UserRepository::new(db.pool.clone());
        let email_code_repo = EmailCodeRepository::new(db.pool.clone());
        let rbac_repo = RbacRepository::new(db.pool.clone());
        let email_sender: Arc<dyn EmailSender> = match &cfg.smtp {
            Some(smtp) => Arc::new(crate::auth::SmtpEmailSender::new(smtp.clone())),
            None => Arc::new(ConsoleEmailSender),
        };
        AuthService::new(user_repo, email_code_repo, rbac_repo, email_sender, cfg.clone())
    });

    let app_state = AppState {
        db,
        cfg,
        auth_service,
        storage_service,
    };

    // Middleware that adds high level tracing to a Service.
    // Trace comes with good defaults but also supports customizing many aspects of the output:
    // https://docs.rs/tower-http/latest/tower_http/trace/index.html
    let trace_layer = telemetry::trace_layer();

    // Sets 'x-request-id' header with randomly generated uuid v7.
    let request_id_layer = middleware::request_id_layer();

    // Propagates 'x-request-id' header from the request to the response.
    let propagate_request_id_layer = middleware::propagate_request_id_layer();

    // Layer that applies the Cors middleware which adds headers for CORS.
    let cors_layer = middleware::cors_layer(&app_state.cfg.cors_origins);

    // Layer that applies the Timeout middleware, which sets a timeout for requests.
    // The default value is 15 seconds.
    let timeout_layer = middleware::timeout_layer();

    // Any trailing slashes from request paths will be removed. For example, a request with `/foo/`
    // will be changed to `/foo` before reaching the internal service.
    let normalize_path_layer = middleware::normalize_path_layer();

    // Security headers: X-Content-Type-Options, X-Frame-Options, HSTS (production only).
    let is_production = matches!(app_state.cfg.env, cfg::Environment::Production);

    // Create the router with the routes.
    let router = routes::router();

    // Combine all the routes and apply the middleware layers.
    // The order of the layers is important. The first layer is the outermost layer.
    let app = Router::new()
        .merge(router)
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .layer(middleware::x_content_type_options_layer())
        .layer(middleware::x_frame_options_layer());
    let app = if is_production {
        app.layer(middleware::hsts_layer())
    } else {
        app
    };
    app.layer(normalize_path_layer)
        .layer(cors_layer)
        .layer(timeout_layer)
        .layer(propagate_request_id_layer)
        .layer(trace_layer)
        .layer(request_id_layer)
        .with_state(app_state)
}
