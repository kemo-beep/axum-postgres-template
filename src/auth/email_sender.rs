//! Email sender trait for auth flows.
//!
//! ConsoleEmailSender logs to tracing (dev). SmtpEmailSender (Phase 4) sends via SMTP.

use std::future::Future;

/// Sends transactional emails for auth (login codes, password reset).
pub trait EmailSender: Send + Sync {
    /// Sends a 6-digit login code to the given email.
    fn send_login_code<'a>(
        &'a self,
        to: &'a str,
        code: &'a str,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), anyhow::Error>> + Send + 'a>>;
}

/// Logs emails to tracing instead of sending. Used when SMTP is not configured.
#[derive(Clone, Default)]
pub struct ConsoleEmailSender;

impl EmailSender for ConsoleEmailSender {
    fn send_login_code<'a>(
        &'a self,
        to: &'a str,
        code: &'a str,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), anyhow::Error>> + Send + 'a>> {
        Box::pin(async move {
            tracing::info!(to = %to, code = %code, "Would send login code email (SMTP not configured)");
            Ok(())
        })
    }
}

/// Sends emails via SMTP. Use when SMTP is configured.
pub struct SmtpEmailSender {
    config: crate::cfg::SmtpConfig,
}

impl SmtpEmailSender {
    pub fn new(config: crate::cfg::SmtpConfig) -> Self {
        Self { config }
    }
}

impl EmailSender for SmtpEmailSender {
    fn send_login_code<'a>(
        &'a self,
        to: &'a str,
        code: &'a str,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), anyhow::Error>> + Send + 'a>> {
        let config = self.config.clone();
        let to = to.to_string();
        let code = code.to_string();
        Box::pin(async move {
            use lettre::transport::smtp::authentication::Credentials;
            use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

            let email = Message::builder()
                .from(config.from.parse().map_err(|e: lettre::address::AddressError| anyhow::anyhow!("{}", e))?)
                .to(to.parse().map_err(|e: lettre::address::AddressError| anyhow::anyhow!("{}", e))?)
                .subject("Your login code")
                .body(format!("Your login code is: {}. It expires in 15 minutes.", code))?;

            let creds = Credentials::new(config.user.clone(), config.password.clone());
            let mailer =
                AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)?
                    .port(config.port)
                    .credentials(creds)
                    .build();

            mailer.send(email).await?;
            Ok(())
        })
    }
}
