# Email DNS Setup: DKIM, DMARC, SPF

Transactional emails (login codes, password reset, billing reminders) are sent via SMTP. To avoid the spam folder and improve deliverability, configure DNS records for your sending domain.

## Overview

| Record | Purpose |
|--------|---------|
| **SPF** | Tells receiving servers which IPs/hosts are allowed to send mail for your domain |
| **DKIM** | Signs emails cryptographically so receivers can verify they came from you |
| **DMARC** | Tells receivers what to do when SPF/DKIM fail; provides reporting |

Configure these on the subdomain used in `MAIL_FROM` (e.g. `noreply@mail.yourdomain.com` → DNS on `mail.yourdomain.com` or root).

## Option A: Use a Transactional Email Provider (Recommended)

Providers like **Resend**, **Postmark**, **SendGrid**, or **Mailgun** handle DKIM and SPF for you:

1. Create an account and add/verify your domain.
2. Add the DNS records they provide (usually 2–3 CNAME records for DKIM).
3. Use their SMTP credentials in `.env`:

   ```
   SMTP_HOST=smtp.resend.com
   SMTP_PORT=465
   SMTP_USER=resend
   SMTP_PASSWORD=re_xxxx
   MAIL_FROM=noreply@yourdomain.com
   ```

4. They typically publish SPF and provide DKIM keys automatically. No manual DNS setup required beyond what their dashboard shows.

## Option B: Custom SMTP with Self-Managed DNS

If you run your own SMTP (e.g. your own server or a VPS SMTP relay):

### 1. SPF (TXT record)

Add a TXT record for your domain or subdomain:

| Type | Name  | Value |
|------|-------|-------|
| TXT  | `@` or `mail` | `v=spf1 include:_spf.yourprovider.com ~all` |

Replace `include:_spf.yourprovider.com` with your SMTP provider’s SPF include. If sending from your own IP:

```
v=spf1 ip4:YOUR_SERVER_IP ~all
```

- `~all` = soft fail for non-matching senders (recommended at first)
- `-all` = hard fail (use once you’re confident)

### 2. DKIM (TXT record)

Your SMTP provider or server generates a DKIM key pair. They give you:

- A **selector** (e.g. `dkim` or `default`)
- A **public key** (long string)

Add a TXT record:

| Type | Name             | Value        |
|------|------------------|--------------|
| TXT  | `dkim._domainkey` or `selector._domainkey` | `v=DKIM1; k=rsa; p=YOUR_PUBLIC_KEY` |

The app’s `lettre` crate can sign with DKIM if you configure it. Without DKIM signing in the app, this record alone does nothing; your provider must sign, or you need to add DKIM support to the email sender.

### 3. DMARC (TXT record)

Add a DMARC policy:

| Type | Name    | Value |
|------|---------|-------|
| TXT  | `_dmarc` | `v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com` |

Start with `p=none` to gather reports without rejecting mail. After you’re confident:

- `p=quarantine` – send failures to spam
- `p=reject` – reject failures

`rua` is where aggregate reports go (optional but useful).

### 4. Use a Subdomain for Sending

Best practice: send from a subdomain like `mail.yourdomain.com` or `noreply@mail.yourdomain.com`:

1. Set `MAIL_FROM=noreply@mail.yourdomain.com`.
2. Add SPF, DKIM, DMARC on `mail.yourdomain.com` (or delegate: `mail` CNAME).
3. Your main domain’s reputation stays separate if something goes wrong.

## Verify Configuration

After adding records (allow 5–30 minutes for propagation):

- [Mail-Tester](https://www.mail-tester.com/) – send a test email and get a deliverability score.
- [MXToolbox](https://mxtoolbox.com/) – check SPF, DKIM, DMARC.
- Send a test to Gmail/Outlook and check headers: `Authentication-Results` should show `spf=pass` and `dkim=pass` when set up correctly.

## Troubleshooting

- **Emails in spam:** Ensure SPF and DKIM pass; add DMARC; avoid spammy content; warm up the domain.
- **SPF too many lookups:** SPF allows ~10 DNS lookups; minimize `include:` entries.
- **DKIM fails:** Check selector and public key; ensure the sending server signs with the matching private key.
