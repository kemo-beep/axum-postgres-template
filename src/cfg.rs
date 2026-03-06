use serde::Deserialize;
use std::{
    net::{Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
};

pub type Config = Arc<Configuration>;

/// SMTP configuration for transactional emails.
#[derive(Clone, Debug)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub from: String,
}

/// R2 / S3 storage configuration.
#[derive(Clone, Debug)]
pub struct R2Config {
    pub account_id: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub bucket_name: String,
    pub endpoint: String,
}

/// Stripe configuration. Backend-only: publishable_key optional.
#[derive(Clone, Debug)]
pub struct StripeConfig {
    pub secret_key: String,
    pub webhook_secret: String,
    pub publishable_key: Option<String>,
}

/// Application configuration built from environment variables.
#[derive(Clone)]
pub struct Configuration {
    /// The environment in which to run the application.
    pub env: Environment,

    /// The address to listen on.
    pub listen_address: SocketAddr,
    /// The port to listen on.
    pub app_port: u16,

    /// The DSN for the database. Currently, only PostgreSQL is supported.
    pub db_dsn: String,
    /// The maximum number of connections for the PostgreSQL pool.
    pub db_pool_max_size: u32,

    /// JWT secret for signing access tokens. Required for auth.
    pub jwt_secret: Option<String>,
    /// JWT access token expiry in seconds. Default 3600 (1 hour).
    pub jwt_expiry_secs: u64,

    /// SMTP config for sending emails. None = no-op / log-only in dev.
    pub smtp: Option<SmtpConfig>,
    /// R2 storage config. None = storage endpoints disabled.
    pub r2: Option<R2Config>,
    /// Stripe config. None = billing endpoints disabled.
    pub stripe: Option<StripeConfig>,

    /// CORS allowed origins. Comma-separated, or "*" for any. Default "*" in dev.
    pub cors_origins: Vec<String>,

    /// Google OAuth: client ID. None = Google login disabled.
    pub google_client_id: Option<String>,
    /// Google OAuth: client secret.
    pub google_client_secret: Option<String>,
    /// Base URL for OAuth redirect (e.g. https://api.example.com). Used to build redirect_uri.
    pub base_url: String,
    /// Frontend app URL for OAuth callback redirect. When set, Google callback redirects here with ?token= instead of returning JSON.
    pub frontend_url: Option<String>,

    /// Auth cookie name for browser-based auth. Default "session".
    pub cookie_name: String,

    /// Max failed password login attempts before lockout. 0 = disabled. Default 5.
    pub login_lockout_max_attempts: u32,
    /// Lockout duration in minutes. Default 15.
    pub login_lockout_duration_minutes: u64,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub enum Environment {
    Development,
    Production,
}

impl Configuration {
    /// Creates a new configuration from environment variables.
    pub fn new() -> Config {
        let env = env_var("APP_ENVIRONMENT")
            .parse::<Environment>()
            .expect("Unable to parse the value of the APP_ENVIRONMENT environment variable. Please make sure it is either \"development\" or \"production\".");

        let app_port = env_var("PORT")
            .parse::<u16>()
            .expect("Unable to parse the value of the PORT environment variable. Please make sure it is a valid unsigned 16-bit integer");

        let db_dsn = env_var("DATABASE_URL");

        let db_pool_max_size = env_var("DATABASE_POOL_MAX_SIZE")
            .parse::<u32>()
            .expect("Unable to parse the value of the DATABASE_POOL_MAX_SIZE environment variable. Please make sure it is a valid unsigned 32-bit integer.");

        let listen_address = SocketAddr::from((Ipv6Addr::UNSPECIFIED, app_port));

        let jwt_secret = env_var_opt("JWT_SECRET");
        let jwt_expiry_secs = env_var_opt("JWT_EXPIRY_SECS")
            .and_then(|s| s.parse().ok())
            .unwrap_or(3600);

        let smtp = match (
            env_var_opt("SMTP_HOST"),
            env_var_opt("SMTP_PORT"),
            env_var_opt("SMTP_USER"),
            env_var_opt("SMTP_PASSWORD"),
            env_var_opt("MAIL_FROM"),
        ) {
            (Some(host), Some(port), Some(user), Some(password), Some(from)) => Some(SmtpConfig {
                host,
                port: port.parse().unwrap_or(587),
                user,
                password,
                from,
            }),
            _ => None,
        };

        let r2 = match (
            env_var_opt("R2_ACCOUNT_ID"),
            env_var_opt("R2_ACCESS_KEY_ID"),
            env_var_opt("R2_SECRET_ACCESS_KEY"),
            env_var_opt("R2_BUCKET_NAME"),
            env_var_opt("R2_ENDPOINT"),
        ) {
            (
                Some(account_id),
                Some(access_key_id),
                Some(secret_access_key),
                Some(bucket_name),
                Some(endpoint),
            ) => Some(R2Config {
                account_id,
                access_key_id,
                secret_access_key,
                bucket_name,
                endpoint,
            }),
            _ => None,
        };

        let stripe = match (
            env_var_opt("STRIPE_SECRET_KEY"),
            env_var_opt("STRIPE_WEBHOOK_SECRET"),
        ) {
            (Some(secret_key), Some(webhook_secret)) => Some(StripeConfig {
                secret_key,
                webhook_secret,
                publishable_key: env_var_opt("STRIPE_PUBLISHABLE_KEY"),
            }),
            _ => None,
        };

        let cors_origins: Vec<String> = env_var_opt("CORS_ORIGINS")
            .map(|s| {
                s.split(',')
                    .map(str::trim)
                    .filter(|x| !x.is_empty())
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_else(|| vec!["*".to_string()]);

        let google_client_id = env_var_opt("GOOGLE_CLIENT_ID");
        let google_client_secret = env_var_opt("GOOGLE_CLIENT_SECRET");
        let base_url =
            env_var_opt("BASE_URL").unwrap_or_else(|| format!("http://localhost:{}", app_port));
        let frontend_url = env_var_opt("FRONTEND_URL");
        let cookie_name = env_var_opt("COOKIE_NAME").unwrap_or_else(|| "session".to_string());
        let login_lockout_max_attempts = env_var_opt("LOGIN_LOCKOUT_MAX_ATTEMPTS")
            .and_then(|s| s.parse().ok())
            .unwrap_or(5);
        let login_lockout_duration_minutes = env_var_opt("LOGIN_LOCKOUT_DURATION_MINUTES")
            .and_then(|s| s.parse().ok())
            .unwrap_or(15);

        Arc::new(Configuration {
            env,
            listen_address,
            app_port,
            db_dsn,
            db_pool_max_size,
            jwt_secret,
            jwt_expiry_secs,
            smtp,
            r2,
            stripe,
            cors_origins,
            google_client_id,
            google_client_secret,
            base_url,
            frontend_url,
            cookie_name,
            login_lockout_max_attempts,
            login_lockout_duration_minutes,
        })
    }

    /// Sets the database DSN.
    /// This method is used in tests to override the database DSN.
    pub fn set_dsn(&mut self, db_dsn: String) {
        self.db_dsn = db_dsn
    }
}

impl FromStr for Environment {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "development" => Ok(Environment::Development),
            "production" => Ok(Environment::Production),
            _ => Err(format!(
                "Invalid environment: {}. Please make sure it is either \"development\" or \"production\".",
                s
            )),
        }
    }
}

/// Reads a required env var. Panics with a clear message if missing.
pub fn env_var(name: &str) -> String {
    std::env::var(name)
        .map_err(|e| format!("{}: {}", name, e))
        .expect("Missing environment variable")
}

/// Returns the value of an environment variable, or None if unset.
pub fn env_var_opt(name: &str) -> Option<String> {
    std::env::var(name).ok()
}
