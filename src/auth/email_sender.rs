//! Email sender trait for auth flows.
//!
//! ConsoleEmailSender logs to tracing (dev). SmtpEmailSender sends via SMTP with HTML and plain text templates.

use std::future::Future;

use askama::Template;

use crate::auth::email_templates::{
    LoginCodeHtml, LoginCodePlain, PasswordResetHtml, PasswordResetPlain,
};

/// Sends transactional emails for auth (login codes, password reset).
pub trait EmailSender: Send + Sync {
    /// Sends a 6-digit login code to the given email.
    fn send_login_code<'a>(
        &'a self,
        to: &'a str,
        code: &'a str,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), anyhow::Error>> + Send + 'a>>;

    /// Sends a password reset link to the given email.
    fn send_password_reset<'a>(
        &'a self,
        to: &'a str,
        reset_link: &'a str,
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

    fn send_password_reset<'a>(
        &'a self,
        to: &'a str,
        reset_link: &'a str,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), anyhow::Error>> + Send + 'a>> {
        Box::pin(async move {
            tracing::info!(to = %to, reset_link = %reset_link, "Would send password reset email (SMTP not configured)");
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
            use lettre::message::MultiPart;
            use lettre::transport::smtp::authentication::Credentials;
            use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

            let plain = LoginCodePlain { code: &code }.render()?;
            let html = LoginCodeHtml { code: &code }.render()?;
            let email = Message::builder()
                .from(
                    config
                        .from
                        .parse()
                        .map_err(|e: lettre::address::AddressError| anyhow::anyhow!("{}", e))?,
                )
                .to(to
                    .parse()
                    .map_err(|e: lettre::address::AddressError| anyhow::anyhow!("{}", e))?)
                .subject("Your login code")
                .multipart(MultiPart::alternative_plain_html(plain, html))?;

            let creds = Credentials::new(config.user.clone(), config.password.clone());
            let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)?
                .port(config.port)
                .credentials(creds)
                .build();

            mailer.send(email).await?;
            Ok(())
        })
    }

    fn send_password_reset<'a>(
        &'a self,
        to: &'a str,
        reset_link: &'a str,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), anyhow::Error>> + Send + 'a>> {
        let config = self.config.clone();
        let to = to.to_string();
        let reset_link = reset_link.to_string();
        Box::pin(async move {
            use lettre::message::MultiPart;
            use lettre::transport::smtp::authentication::Credentials;
            use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

            let plain = PasswordResetPlain {
                reset_link: &reset_link,
            }
            .render()?;
            let html = PasswordResetHtml {
                reset_link: &reset_link,
            }
            .render()?;
            let email = Message::builder()
                .from(
                    config
                        .from
                        .parse()
                        .map_err(|e: lettre::address::AddressError| anyhow::anyhow!("{}", e))?,
                )
                .to(to
                    .parse()
                    .map_err(|e: lettre::address::AddressError| anyhow::anyhow!("{}", e))?)
                .subject("Password reset")
                .multipart(MultiPart::alternative_plain_html(plain, html))?;

            let creds = Credentials::new(config.user.clone(), config.password.clone());
            let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)?
                .port(config.port)
                .credentials(creds)
                .build();

            mailer.send(email).await?;
            Ok(())
        })
    }
}
