# Axum + PostgreSQL SaaS Backend Template

Production-ready starter for building SaaS backends with [Axum](https://github.com/tokio-rs/axum) and [PostgreSQL](https://www.postgresql.org/). Use this template to scaffold auth, RBAC, Stripe/Polar, R2, email, and more.

See [docs/checklist.md](docs/checklist.md) for the full production-readiness guide.

Inspired by [Zero To Production In Rust](https://www.zero2prod.com) and [realworld-axum-sqlx](https://github.com/launchbadge/realworld-axum-sqlx).

## Tech Stack

| Crate | Purpose |
|-------|---------|
| [Axum](https://github.com/tokio-rs/axum) | Web framework built on Tokio, Tower, and Hyper |
| [SQLx](https://github.com/launchbadge/sqlx) | Async PostgreSQL with compile-time checked queries |
| [Tracing](https://github.com/tokio-rs/tracing) | Structured logging and observability |
| [Chrono](https://github.com/chronotope/chrono) | Date and time handling |
| [Serde](https://serde.rs/) | JSON serialization |
| [Uuid](https://github.com/uuid-rs/uuid) | UUID generation and parsing |
| [argon2](https://github.com/RustCrypto/password-hashes) | Password hashing |
| [jsonwebtoken](https://github.com/Keats/jsonwebtoken) | JWT for auth |
| [lettre](https://github.com/lettre/lettre) | SMTP transactional email |
| [oauth2](https://github.com/ramosbugs/oauth2-rs) | Google OAuth |
| [tower_governor](https://github.com/benwis/tower-governor) | Rate limiting |
| [utoipa](https://github.com/juhaku/utoipa) | OpenAPI / Swagger |

Included out of the box: migrations at startup, connection pooling with retry, health check, **Swagger UI** (interactive API docs at `/swagger-ui`), structured logging, request timeouts, CORS, request IDs, security headers, graceful shutdown, and **live reload** via `cargo watch`. See [Cargo.toml](./Cargo.toml) for the full dependency list.

## How to Run

### Prerequisites

- [Rust](https://www.rust-lang.org/)
- [Docker](https://www.docker.com/) (for running Postgres locally)
- [sqlx-cli](https://github.com/launchbadge/sqlx) for migrations

### Quick Start

```bash
# 1. Install sqlx-cli
cargo install sqlx-cli --features postgres

# 2. Start Postgres (Docker)
docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=password postgres

# 3. Clone and configure
git clone https://github.com/koskeller/axum-postgres-template
cd axum-postgres-template
cp .env.sample .env

# 4. Setup DB and run
sqlx db setup
cargo run

# Then open Swagger UI at http://localhost:8080/swagger-ui
```

### Running the Server

```bash
# One-time run
cargo run

# With live reload (restarts on file changes)
cargo install cargo-watch   # first time only
cargo watch -q -x run
# or
make dev
```

The server listens on `http://127.0.0.1:8080` by default (or `PORT` from `.env`, e.g. `http://localhost:7474`).

### Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check (liveness/readiness) |
| `GET /swagger-ui` | Swagger UI — interactive API docs |
| `GET /api-docs/openapi.json` | OpenAPI JSON spec |
| `POST /v1/auth/send-code` | Send 6-digit login code to email |
| `POST /v1/auth/verify-code` | Verify code, return access token |
| `POST /v1/auth/register` | Register with email + password |
| `POST /v1/auth/login` | Login with email + password |
| `GET /v1/auth/google` | Redirect to Google OAuth |
| `GET /v1/auth/google/callback` | OAuth callback |
| `GET /v1/auth/me` | Current user (Bearer token required) |
| `GET /v1/files/{key}/url` | Presigned URL (auth, R2 required) |
| `POST /webhooks/stripe` | Stripe webhook endpoint |

Example URLs when using `PORT=7474`: `http://localhost:7474/health`, `http://localhost:7474/swagger-ui`, `http://localhost:7474/api-docs/openapi.json`.

### API Documentation (Swagger)

OpenAPI documentation is auto-generated from `#[utoipa::path(...)]` annotations. Add them to new handlers and register paths in the `ApiDoc` struct in `src/lib.rs`.

### Environment Variables

From [.env.sample](.env.sample):

| Variable | Description |
|----------|-------------|
| `APP_ENVIRONMENT` | `development` or `production` |
| `PORT` | Server port (default: 8080) |
| `DATABASE_URL` | PostgreSQL connection string |
| `DATABASE_POOL_MAX_SIZE` | Connection pool size |
| `DATABASE_NAME` | Base DB name (for tests; must match DB in `DATABASE_URL`) |
| `JWT_SECRET` | Required for auth endpoints (min 32 chars) |
| `JWT_EXPIRY_SECS` | Access token expiry (default: 3600) |
| `BASE_URL` | Base URL for OAuth redirect (e.g. http://localhost:8080) |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | Google OAuth (optional) |
| `SMTP_*`, `MAIL_FROM` | SMTP for transactional email (optional; unset = log-only) |
| `R2_*` | Cloudflare R2 / S3 storage (optional) |
| `STRIPE_*` | Stripe payments (optional) |
| `CORS_ORIGINS` | Comma-separated origins or `*` |
| `RUST_LOG` | Log level (e.g. `server=debug,tower_http=info,sqlx=info`) |

### Auth flows

- **Email code**: `POST /v1/auth/send-code` → user receives 6-digit code → `POST /v1/auth/verify-code` → returns access token. Rate limited (5/min per IP).
- **Email + password**: `POST /v1/auth/register` or `POST /v1/auth/login` → returns access token.
- **Google OAuth**: `GET /v1/auth/google` (redirect) → user signs in → callback returns token.
- **Protected routes**: add `Authorization: Bearer <token>` header.

### Live Reload (Development)

Watch source files and restart the server on changes:

```bash
cargo install cargo-watch
cargo watch -q -x run
```

Or use the Makefile target:

```bash
make dev
```

To format JSON logs with [jq](https://github.com/jqlang/jq):

```bash
cargo watch -q -x run | jq .
```

### Testing

Integration tests use a real PostgreSQL database. Ensure Postgres is running and `DATABASE_URL` in `.env` points to a reachable instance (tests create a separate DB per run).

```bash
cargo test
```

### Offline / CI Builds

To build without a live database (e.g. in CI):

```bash
cargo sqlx prepare
```

Then build with `SQLX_OFFLINE=true`. See [sqlx offline mode](https://github.com/launchbadge/sqlx/blob/main/sqlx-cli/README.md#enable-building-in-offline-mode-with-query) for details.

## Docker Deployment

Build and run using the provided [Dockerfile](Dockerfile):

```bash
# Build the image
docker build -t axum-saas-backend .

# Run (provide DATABASE_URL and JWT_SECRET at minimum)
docker run -p 8080:8080 \
  -e DATABASE_URL="postgres://user:pass@host:5432/dbname" \
  -e APP_ENVIRONMENT=production \
  -e JWT_SECRET="your-secret-min-32-characters-long" \
  axum-saas-backend
```

The image does not include Postgres; you must provide a running database and `DATABASE_URL`. Port 8080 is exposed. Migrations run automatically at startup. For auth to work, set `JWT_SECRET`.

## Architecture

The template follows a layered, feature-based structure (see [.cursor/rules/backend-architecture.mdc](.cursor/rules/backend-architecture.mdc) and [docs/checklist.md](docs/checklist.md)):

- **Handlers** — Thin; extract input, call services, return responses
- **Services** — Business logic and orchestration
- **Repositories** — Database access only; no HTTP details

### Project structure

```
src/
├── lib.rs, main.rs
├── api_error.rs, cfg.rs, db.rs, telemetry.rs, middleware.rs
├── types/          # UserId, TenantId
├── auth/           # Email code, Google OAuth, email+password, JWT, RBAC
├── billing/        # Stripe webhooks
├── storage/        # R2 presigned URLs
├── services/       # JobQueue trait (tokio::spawn; Redis upgrade path)
└── routes/         # /health, /v1/*, /webhooks/*, /swagger-ui
```

Mounted routes: health check (readiness), versioned API at `/v1/` (auth, files), webhooks at `/webhooks/`, and Swagger UI.

## Production Readiness Checklist

The [docs/checklist.md](docs/checklist.md) covers:

- **Code quality & architecture** — Layering, domain types, errors
- **Core infra** — PostgreSQL, SQLx, configuration
- **Auth** — Email code, Google OAuth, email+password
- **Authorization** — RBAC, resource-level access, API keys
- **Security** — Rate limiting, CORS, headers, audit logging
- **Payments** — Stripe / Polar.sh subscriptions and one-time purchases
- **Storage** — Cloudflare R2 (S3-compatible)
- **Email** — SMTP transactional emails
- **Observability** — Logging, metrics, health checks, tracing
- **Background jobs** — Queues, async processing
- **Deployment** — Dockerfile, migrations, secrets, zero-downtime

## Example Handler

```rust
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExampleReq {
    pub input: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExampleResp {
    pub output: String,
}

pub async fn example(
    State(state): State<AppState>,
    req: Result<Json<ExampleReq>, JsonRejection>,
) -> Result<Json<ExampleResp>, ApiError> {
    let Json(req) = req?;

    if req.input.is_empty() {
        return Err(ApiError::InvalidRequest(
            "'input' should not be empty".to_string(),
        ));
    }

    let resp = ExampleResp {
        output: "hello".to_string(),
    };
    Ok(Json(resp))
}
```

## Contributing

Contributions are welcome. Open an issue for tasks that need attention or improvements.
