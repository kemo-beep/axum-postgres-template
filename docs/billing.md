# Billing: Production-Grade Flows

## Access Control Semantics

Pro access is granted when subscription status is one of:

| Status    | Pro access | Notes                                      |
|-----------|------------|--------------------------------------------|
| `active`  | Yes        | Normal paid                                |
| `trialing`| Yes        | Trial period                               |
| `past_due`| Yes        | Payment failed, Stripe retrying; grace     |
| `unpaid`  | No         | Stripe exhausted retries; cut access       |
| `canceled`| No         | Subscription ended                         |

`get_subscription_by_org` and `get_user_active_plan_name` filter on `status IN ('active', 'trialing', 'past_due')`.

## Stripe Customer Portal Configuration

In Stripe Dashboard → Settings → Billing → Customer portal:

- Enable **Cancel subscriptions** with **At end of billing period** (recommended).
- Enable **Update payment method**.
- Enable **View invoice history**.
- Set return URL to org billing tab: `{origin}/orgs/{org_id}?tab=billing`.
- Enable **Resume subscription** for canceled-but-not-ended.

## Cancel and Resume

- **Cancel at period end:** User keeps Pro until `current_period_end`. Stripe sets `cancel_at_period_end=true`.
- **Resume:** User can click "Resume" in Portal before period end; we sync via webhooks.
- **After period ends:** Status becomes `canceled`; user must re-subscribe (new checkout).

## Payment Failed (invoice.payment_failed)

When a subscription renewal payment fails:

- **Transaction logged:** A `payment_failed` subscription transaction is recorded.
- **User notified:** An email is sent to the billing/customer email with the hosted invoice URL and a link to update payment (org billing tab when `frontend_url` is configured).
- **Retry logic:** Stripe automatically retries failed subscription payments on a schedule (e.g. days 3, 5, 7). No application retry logic is needed.
- **Grace period:** Status becomes `past_due` during retries; Pro access continues until Stripe exhausts retries and marks the subscription `unpaid`.

Configure Smart Retries or custom retry schedules in Stripe Dashboard → Settings → Billing → Revenue recovery.

## Proration

Plan changes (upgrade/downgrade) use Stripe's default proration behavior (`create_prorations`): proration line items are created and appear on the next invoice. No application-level proration handling is required.

## Refunds and Token Balance

For token package (one-time) purchases:

- `payment_intent_id` is stored when crediting tokens so refunds can be matched.
- On `charge.refunded`, we debit the org's token balance and record a refund credit transaction.
- Idempotency: duplicate refund events are ignored via `has_refund_for_payment_intent`.

## Background Reconciliation

A background job runs hourly to fix drift from missed webhooks. It finds subscriptions where `cancel_at_period_end=true`, `current_period_end < now()`, and status still active → sets `status='canceled'`.
