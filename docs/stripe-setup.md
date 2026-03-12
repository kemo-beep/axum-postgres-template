# Stripe Account Setup & Chargeback Reduction

## Account Setup

### Business Verification

1. **Stripe Dashboard → Settings → Business**
   - Provide legal business name, address, and tax ID (EIN for US).
   - Verify identity if prompted (ID, proof of address).
2. **Payout details**
   - Add bank account for payouts (Settings → Payouts).
   - Verify micro-deposits if required.

### Tax Configuration

- **Settings → Tax** – Enable Stripe Tax if you need automatic tax calculation.
- For manual tax: store customer addresses and apply rules per region.

### Public Product Info

- Ensure product names and descriptions in Stripe match what users see in the app.
- Use clear pricing display; avoid hidden fees to reduce disputes.

---

## Reducing Chargebacks & Disputes

### 1. Clear Billing Descriptor

The text on customers’ bank/credit card statements should be recognizable:

- **Stripe Dashboard → Settings → Branding**
- Set **Statement descriptor** (e.g. `YOURCOMPANY` or `YOURCOMPANY*PRODUCT`).
- Keep it short, clear, and consistent with your brand.

### 2. Confirmation Emails

- Send receipts or confirmations for every charge.
- This app sends billing-related emails (payment failed, trial ending, past-due) via `EmailSender`.
- Ensure `MAIL_FROM` and branding match your product so customers recognize the sender.

### 3. Visible Billing Information

- Show prices and renewal dates before checkout.
- Use Stripe Checkout with clear product description and terms.
- Link to your Terms of Service and refund policy in the Checkout flow.

### 4. Easy Self-Service Cancellation

- Enable **Cancel subscriptions** in Customer Portal (At end of billing period).
- Document how to cancel in help/support.
- Reduces “I couldn’t cancel” as a dispute reason.

### 5. Refund Policy

- Implement clear refund logic and publish it.
- Process refunds promptly; this app handles `charge.refunded` for token debits.
- Refunding before a dispute can prevent chargebacks.

### 6. Respond to Disputes Quickly

- **Stripe Dashboard → Disputes**
- Submit evidence before the deadline (usually 7–21 days).
- Include: customer agreement, login/IP logs, receipts, support history.
- Use the built-in evidence form; attach PDFs if helpful.

### 7. Fraud Prevention

- Use Stripe Radar (often on by default).
- Consider 3D Secure (SCA) for high-risk regions.
- Block obvious fraud (e.g. stolen cards) via Radar rules.

### 8. Good Customer Communication

- Provide clear support contact (e.g. support@yourdomain.com).
- Respond quickly to billing questions.
- Document policies (refunds, cancellations) on a public page.

---

## Quick Checklist

- [ ] Business verified; payout details set
- [ ] Statement descriptor set and recognizable
- [ ] Confirmation emails sent for charges
- [ ] Billing terms and cancellation clearly documented
- [ ] Customer Portal configured (see [billing.md](billing.md))
- [ ] Refund process defined and published
- [ ] Dispute alerts enabled; evidence process documented
- [ ] Support contact visible and responsive
