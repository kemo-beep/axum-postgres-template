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
