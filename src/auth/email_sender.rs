//! Email sender trait for auth flows.
//!
//! ConsoleEmailSender logs to tracing (dev). SmtpEmailSender sends via SMTP with HTML and plain text templates.

use std::future::Future;
use std::time::Duration;

const SMTP_TIMEOUT: Duration = Duration::from_secs(15);

use askama::Template;

use crate::auth::email_templates::{
    ContactFormHtml, ContactFormPlain, LoginCodeHtml, LoginCodePlain, PastDueReminderHtml,
    PastDueReminderPlain, PaymentFailedHtml, PaymentFailedPlain, PasswordResetHtml,
    PasswordResetPlain, TrialEndingSoonHtml, TrialEndingSoonPlain,
};

/// Sends transactional emails for auth (login codes, password reset) and billing (payment failed).
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

    /// Sends a payment failed notification with invoice URL and optional update payment link.
    fn send_payment_failed<'a>(
        &'a self,
        to: &'a str,
        hosted_invoice_url: Option<&'a str>,
        update_payment_url: Option<&'a str>,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), anyhow::Error>> + Send + 'a>>;

    /// Sends a trial ending soon reminder (plan_name, formatted trial_end date, optional billing URL).
    fn send_trial_ending_soon<'a>(
        &'a self,
        to: &'a str,
        plan_name: &'a str,
        trial_end: &'a str,
        billing_url: Option<&'a str>,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), anyhow::Error>> + Send + 'a>>;

    /// Sends a past-due reminder (optional hosted invoice URL, optional billing URL).
    fn send_past_due_reminder<'a>(
        &'a self,
        to: &'a str,
        hosted_invoice_url: Option<&'a str>,
        billing_url: Option<&'a str>,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), anyhow::Error>> + Send + 'a>>;

    /// Sends a contact form submission to the support inbox.
    fn send_contact_form<'a>(
        &'a self,
        to: &'a str,
        from_name: &'a str,
        from_email: &'a str,
        subject: &'a str,
        message: &'a str,
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

    fn send_payment_failed<'a>(
        &'a self,
        to: &'a str,
        hosted_invoice_url: Option<&'a str>,
        update_payment_url: Option<&'a str>,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), anyhow::Error>> + Send + 'a>> {
        Box::pin(async move {
            tracing::info!(
                to = %to,
                hosted_invoice_url = ?hosted_invoice_url,
                update_payment_url = ?update_payment_url,
                "Would send payment failed email (SMTP not configured)"
            );
            Ok(())
        })
    }

    fn send_trial_ending_soon<'a>(
        &'a self,
        to: &'a str,
        plan_name: &'a str,
        trial_end: &'a str,
        billing_url: Option<&'a str>,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), anyhow::Error>> + Send + 'a>> {
        Box::pin(async move {
            tracing::info!(
                to = %to,
                plan_name = %plan_name,
                trial_end = %trial_end,
                billing_url = ?billing_url,
                "Would send trial ending soon email (SMTP not configured)"
            );
            Ok(())
        })
    }

    fn send_past_due_reminder<'a>(
        &'a self,
        to: &'a str,
        hosted_invoice_url: Option<&'a str>,
        billing_url: Option<&'a str>,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), anyhow::Error>> + Send + 'a>> {
        Box::pin(async move {
            tracing::info!(
                to = %to,
                hosted_invoice_url = ?hosted_invoice_url,
                billing_url = ?billing_url,
                "Would send past-due reminder email (SMTP not configured)"
            );
            Ok(())
        })
    }

    fn send_contact_form<'a>(
        &'a self,
        to: &'a str,
        from_name: &'a str,
        from_email: &'a str,
        subject: &'a str,
        _message: &'a str,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), anyhow::Error>> + Send + 'a>> {
        Box::pin(async move {
            tracing::info!(
                to = %to,
                from_name = %from_name,
                from_email = %from_email,
                subject = %subject,
                "Would send contact form email (SMTP not configured)"
            );
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

            tokio::time::timeout(SMTP_TIMEOUT, mailer.send(email))
                .await
                .map_err(|_| anyhow::anyhow!("SMTP send timed out"))??;
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

            tokio::time::timeout(SMTP_TIMEOUT, mailer.send(email))
                .await
                .map_err(|_| anyhow::anyhow!("SMTP send timed out"))??;
            Ok(())
        })
    }

    fn send_payment_failed<'a>(
        &'a self,
        to: &'a str,
        hosted_invoice_url: Option<&'a str>,
        update_payment_url: Option<&'a str>,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), anyhow::Error>> + Send + 'a>> {
        let config = self.config.clone();
        let to = to.to_string();
        let hosted_invoice_url = hosted_invoice_url.map(String::from);
        let update_payment_url = update_payment_url.map(String::from);
        Box::pin(async move {
            use lettre::message::MultiPart;
            use lettre::transport::smtp::authentication::Credentials;
            use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

            let plain = PaymentFailedPlain {
                hosted_invoice_url: hosted_invoice_url.as_deref(),
                update_payment_url: update_payment_url.as_deref(),
            }
            .render()?;
            let html = PaymentFailedHtml {
                hosted_invoice_url: hosted_invoice_url.as_deref(),
                update_payment_url: update_payment_url.as_deref(),
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
                .subject("Payment failed - action required")
                .multipart(MultiPart::alternative_plain_html(plain, html))?;

            let creds = Credentials::new(config.user.clone(), config.password.clone());
            let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)?
                .port(config.port)
                .credentials(creds)
                .build();

            tokio::time::timeout(SMTP_TIMEOUT, mailer.send(email))
                .await
                .map_err(|_| anyhow::anyhow!("SMTP send timed out"))??;
            Ok(())
        })
    }

    fn send_trial_ending_soon<'a>(
        &'a self,
        to: &'a str,
        plan_name: &'a str,
        trial_end: &'a str,
        billing_url: Option<&'a str>,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), anyhow::Error>> + Send + 'a>> {
        let config = self.config.clone();
        let to = to.to_string();
        let plan_name = plan_name.to_string();
        let trial_end = trial_end.to_string();
        let billing_url = billing_url.map(String::from);
        Box::pin(async move {
            use lettre::message::MultiPart;
            use lettre::transport::smtp::authentication::Credentials;
            use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

            let plain = TrialEndingSoonPlain {
                plan_name: &plan_name,
                trial_end: &trial_end,
                billing_url: billing_url.as_deref(),
            }
            .render()?;
            let html = TrialEndingSoonHtml {
                plan_name: &plan_name,
                trial_end: &trial_end,
                billing_url: billing_url.as_deref(),
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
                .subject("Your trial ends soon")
                .multipart(MultiPart::alternative_plain_html(plain, html))?;

            let creds = Credentials::new(config.user.clone(), config.password.clone());
            let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)?
                .port(config.port)
                .credentials(creds)
                .build();

            tokio::time::timeout(SMTP_TIMEOUT, mailer.send(email))
                .await
                .map_err(|_| anyhow::anyhow!("SMTP send timed out"))??;
            Ok(())
        })
    }

    fn send_past_due_reminder<'a>(
        &'a self,
        to: &'a str,
        hosted_invoice_url: Option<&'a str>,
        billing_url: Option<&'a str>,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), anyhow::Error>> + Send + 'a>> {
        let config = self.config.clone();
        let to = to.to_string();
        let hosted_invoice_url = hosted_invoice_url.map(String::from);
        let billing_url = billing_url.map(String::from);
        Box::pin(async move {
            use lettre::message::MultiPart;
            use lettre::transport::smtp::authentication::Credentials;
            use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

            let plain = PastDueReminderPlain {
                hosted_invoice_url: hosted_invoice_url.as_deref(),
                billing_url: billing_url.as_deref(),
            }
            .render()?;
            let html = PastDueReminderHtml {
                hosted_invoice_url: hosted_invoice_url.as_deref(),
                billing_url: billing_url.as_deref(),
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
                .subject("Subscription payment past due")
                .multipart(MultiPart::alternative_plain_html(plain, html))?;

            let creds = Credentials::new(config.user.clone(), config.password.clone());
            let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)?
                .port(config.port)
                .credentials(creds)
                .build();

            tokio::time::timeout(SMTP_TIMEOUT, mailer.send(email))
                .await
                .map_err(|_| anyhow::anyhow!("SMTP send timed out"))??;
            Ok(())
        })
    }

    fn send_contact_form<'a>(
        &'a self,
        to: &'a str,
        from_name: &'a str,
        from_email: &'a str,
        subject: &'a str,
        message: &'a str,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), anyhow::Error>> + Send + 'a>> {
        let config = self.config.clone();
        let to = to.to_string();
        let from_name = from_name.to_string();
        let from_email = from_email.to_string();
        let subject = subject.to_string();
        let message = message.to_string();
        Box::pin(async move {
            use lettre::message::MultiPart;
            use lettre::transport::smtp::authentication::Credentials;
            use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

            let plain = ContactFormPlain {
                from_name: &from_name,
                from_email: &from_email,
                subject: &subject,
                message: &message,
            }
            .render()?;
            let html = ContactFormHtml {
                from_name: &from_name,
                from_email: &from_email,
                subject: &subject,
                message: &message,
            }
            .render()?;
            let reply_to = format!("{} <{}>", from_name, from_email)
                .parse()
                .map_err(|e: lettre::address::AddressError| anyhow::anyhow!("{}", e))?;
            let email_subject = format!("Contact form: {}", subject);
            let email = Message::builder()
                .from(
                    config
                        .from
                        .parse()
                        .map_err(|e: lettre::address::AddressError| anyhow::anyhow!("{}", e))?,
                )
                .reply_to(reply_to)
                .to(to
                    .parse()
                    .map_err(|e: lettre::address::AddressError| anyhow::anyhow!("{}", e))?)
                .subject(&email_subject)
                .multipart(MultiPart::alternative_plain_html(plain, html))?;

            let creds = Credentials::new(config.user.clone(), config.password.clone());
            let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)?
                .port(config.port)
                .credentials(creds)
                .build();

            tokio::time::timeout(SMTP_TIMEOUT, mailer.send(email))
                .await
                .map_err(|_| anyhow::anyhow!("SMTP send timed out"))??;
            Ok(())
        })
    }
}
