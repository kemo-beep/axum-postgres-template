use axum::Router;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

pub mod auth;
pub mod billing;
pub mod cfg;
pub mod common;
pub mod db;
pub mod middleware;
pub mod org;
pub mod routes;
pub mod services;
pub mod storage;
pub mod telemetry;

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
        auth::routes::password_reset_request,
        auth::routes::password_reset_confirm,
        auth::routes::refresh,
        auth::routes::logout,
        storage::routes::get_presigned_url,
        storage::routes::get_presigned_put_url,
        storage::routes::upload,
        storage::routes::get_presigned_url_workspace,
        storage::routes::get_presigned_put_url_workspace,
        storage::routes::upload_workspace,
        billing::routes::stripe_webhook,
        billing::routes::list_plans,
        billing::routes::list_packages,
        billing::routes::checkout,
        billing::routes::portal,
        billing::routes::subscription_status,
        billing::routes::get_subscription,
        billing::routes::transactions,
        billing::routes::subscription_cancel,
        billing::routes::subscription_change_plan,
        org::routes::list_orgs,
        org::routes::create_org,
        org::routes::get_org,
        org::routes::list_members,
        org::routes::create_invite,
        org::routes::accept_invite,
        org::routes::list_workspaces,
        org::routes::create_workspace,
        auth::rbac_routes::list_roles,
        auth::rbac_routes::list_permissions,
        auth::rbac_routes::list_user_roles,
        auth::rbac_routes::assign_role,
        auth::rbac_routes::revoke_role,
        auth::api_key_routes::create_key,
        auth::api_key_routes::list_keys,
        auth::api_key_routes::revoke_key,
        auth::api_key_routes::rotate_key,
    ),
    components(
        schemas(
            common::ApiErrorResp,
            auth::routes::SendCodeRequest,
            auth::routes::VerifyCodeRequest,
            auth::routes::RegisterRequest,
            auth::routes::LoginRequest,
            auth::routes::PasswordResetRequest,
            auth::routes::PasswordResetConfirmRequest,
            auth::routes::AuthResponse,
            auth::routes::UserResponse,
            storage::routes::PresignedUrlResponse,
            billing::routes::CheckoutRequest,
            billing::routes::UrlResponse,
            billing::routes::ChangePlanRequest,
            org::routes::CreateOrgRequest,
            org::routes::OrgResponse,
            org::routes::CreateWorkspaceRequest,
            org::routes::WorkspaceResponse,
            org::routes::CreateInviteRequest,
            org::routes::InviteResponse,
            org::routes::AcceptInviteRequest,
            org::routes::OrgMemberResponse,
            auth::rbac_routes::RoleResponse,
            auth::rbac_routes::PermissionResponse,
            auth::rbac_routes::AssignRoleRequest,
            auth::api_key_routes::CreateApiKeyRequest,
            auth::api_key_routes::CreateApiKeyResponse,
            auth::api_key_routes::ApiKeyInfoResponse,
        )
    ),
    modifiers(&SecurityAddon)
)]
struct ApiDoc;

/// Returns the OpenAPI spec (e.g. for static generation or export).
pub fn openapi_spec() -> utoipa::openapi::OpenApi {
    ApiDoc::openapi()
}

struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            use utoipa::openapi::security::{
                ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme,
            };
            components.security_schemes.insert(
                "bearer_auth".into(),
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .build(),
                ),
            );
            components.security_schemes.insert(
                "api_key".into(),
                SecurityScheme::ApiKey(utoipa::openapi::security::ApiKey::Header(
                    ApiKeyValue::new("X-API-Key"),
                )),
            );
        }
    }
}

use crate::auth::rbac_service::RbacService;
use crate::auth::service::AuthService;
use crate::billing::service::BillingService;
use crate::org::service::OrgService;
use crate::storage::StorageService;

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub cfg: Config,
    pub auth_service: Option<AuthService>,
    pub api_key_service: Option<crate::auth::api_key_service::ApiKeyService>,
    pub billing_service: Option<BillingService>,
    pub storage_service: Option<StorageService>,
    pub org_service: OrgService,
    pub rbac_service: RbacService,
}

pub fn router(cfg: Config, db: Db, storage_service: Option<StorageService>) -> Router {
    let auth_service = cfg.jwt_secret.as_ref().map(|_| {
        use crate::auth::repository::{EmailCodeRepository, RbacRepository, UserRepository};
        use crate::auth::{ConsoleEmailSender, EmailSender};
        use std::sync::Arc;

        let user_repo = UserRepository::new(db.pool.clone());
        let email_code_repo = EmailCodeRepository::new(db.pool.clone());
        let password_reset_repo =
            crate::auth::repository::PasswordResetRepository::new(db.pool.clone());
        let token_blacklist_repo =
            crate::auth::repository::TokenBlacklistRepository::new(db.pool.clone());
        let rbac_repo = RbacRepository::new(db.pool.clone());
        let email_sender: Arc<dyn EmailSender> = match &cfg.smtp {
            Some(smtp) => Arc::new(crate::auth::SmtpEmailSender::new(smtp.clone())),
            None => Arc::new(ConsoleEmailSender),
        };
        AuthService::new(
            user_repo,
            email_code_repo,
            password_reset_repo,
            token_blacklist_repo,
            rbac_repo,
            email_sender,
            cfg.clone(),
        )
    });

    let billing_service = cfg.stripe.as_ref().map(|stripe_cfg| {
        use crate::auth::repository::UserRepository;
        use crate::billing::repository::BillingRepository;
        use crate::org::repository::OrgRepository;

        let billing_repo = BillingRepository::new(db.pool.clone());
        let user_repo = UserRepository::new(db.pool.clone());
        let org_repo = OrgRepository::new(db.pool.clone());
        BillingService::new(stripe_cfg.clone(), billing_repo, user_repo, org_repo)
    });

    let org_service = {
        use crate::auth::repository::UserRepository;
        use crate::org::repository::OrgRepository;

        let repo = OrgRepository::new(db.pool.clone());
        let user_repo = UserRepository::new(db.pool.clone());
        OrgService::new(repo, user_repo)
    };

    let rbac_service = {
        use crate::auth::repository::RbacRepository;

        let rbac_repo = RbacRepository::new(db.pool.clone());
        RbacService::new(rbac_repo)
    };

    let api_key_service = cfg.jwt_secret.as_ref().map(|_| {
        use crate::auth::api_key_repository::ApiKeyRepository;
        use crate::auth::api_key_service::ApiKeyService;
        use crate::auth::repository::UserRepository;
        use crate::org::repository::OrgRepository;

        let api_key_repo = ApiKeyRepository::new(db.pool.clone());
        let user_repo = UserRepository::new(db.pool.clone());
        let org_repo = OrgRepository::new(db.pool.clone());
        ApiKeyService::new(api_key_repo, user_repo, org_repo)
    });

    let app_state = AppState {
        db,
        cfg,
        auth_service,
        api_key_service,
        billing_service,
        storage_service,
        org_service,
        rbac_service,
    };

    // Background job: reconcile subscriptions that should be canceled (cancel_at_period_end + period ended).
    // Fallback when webhooks are missed. Runs hourly.
    if let Some(billing) = app_state.billing_service.as_ref() {
        let billing = billing.clone();
        tokio::spawn(async move {
            use std::time::Duration;
            let mut interval = tokio::time::interval(Duration::from_secs(3600));
            interval.tick().await; // skip first immediate tick
            loop {
                interval.tick().await;
                match billing.reconcile_stale_cancel_at_period_end().await {
                    Ok(n) if n > 0 => {
                        tracing::info!(count = n, "Subscription reconciliation: marked stale subscriptions as canceled");
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!("Subscription reconciliation failed: {:?}", e);
                    }
                }
            }
        });
    }

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
    let router = routes::router(&app_state);

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
