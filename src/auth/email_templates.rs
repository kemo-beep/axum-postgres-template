//! Askama templates for transactional auth emails.

use askama::Template;

#[derive(Template)]
#[template(path = "emails/login_code.txt")]
pub struct LoginCodePlain<'a> {
    pub code: &'a str,
}

#[derive(Template)]
#[template(path = "emails/login_code.html")]
pub struct LoginCodeHtml<'a> {
    pub code: &'a str,
}

#[derive(Template)]
#[template(path = "emails/password_reset.txt")]
pub struct PasswordResetPlain<'a> {
    pub reset_link: &'a str,
}

#[derive(Template)]
#[template(path = "emails/password_reset.html")]
pub struct PasswordResetHtml<'a> {
    pub reset_link: &'a str,
}

#[derive(Template)]
#[template(path = "emails/payment_failed.txt")]
pub struct PaymentFailedPlain<'a> {
    pub hosted_invoice_url: Option<&'a str>,
    pub update_payment_url: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "emails/payment_failed.html")]
pub struct PaymentFailedHtml<'a> {
    pub hosted_invoice_url: Option<&'a str>,
    pub update_payment_url: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "emails/trial_ending_soon.txt")]
pub struct TrialEndingSoonPlain<'a> {
    pub plan_name: &'a str,
    pub trial_end: &'a str,
    pub billing_url: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "emails/trial_ending_soon.html")]
pub struct TrialEndingSoonHtml<'a> {
    pub plan_name: &'a str,
    pub trial_end: &'a str,
    pub billing_url: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "emails/past_due_reminder.txt")]
pub struct PastDueReminderPlain<'a> {
    pub hosted_invoice_url: Option<&'a str>,
    pub billing_url: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "emails/past_due_reminder.html")]
pub struct PastDueReminderHtml<'a> {
    pub hosted_invoice_url: Option<&'a str>,
    pub billing_url: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "emails/contact_form.txt")]
pub struct ContactFormPlain<'a> {
    pub from_name: &'a str,
    pub from_email: &'a str,
    pub subject: &'a str,
    pub message: &'a str,
}

#[derive(Template)]
#[template(path = "emails/contact_form.html")]
pub struct ContactFormHtml<'a> {
    pub from_name: &'a str,
    pub from_email: &'a str,
    pub subject: &'a str,
    pub message: &'a str,
}
