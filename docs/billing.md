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

## Background Reconciliation

A background job runs hourly to fix drift from missed webhooks. It finds subscriptions where `cancel_at_period_end=true`, `current_period_end < now()`, and status still active → sets `status='canceled'`.
