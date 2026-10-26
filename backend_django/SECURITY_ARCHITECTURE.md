# Security Architecture — MyCyber DLP (Django backend)

This document describes the trust boundaries, data stores, processing model, and
egress surfaces of `backend_django/`. It mirrors the FastAPI architecture in
`backend/SECURITY_ARCHITECTURE.md` but reflects the Django stack. It is the
authoritative reference for auditors and incident response.

## 1. High-level architecture

```
            ┌──────────────────────────────────────────┐
            │              Clients                     │
            │  React/Vite SPA  ·  curl  ·  k6           │
            └────────────┬─────────────────────────────┘
                         │ HTTPS (TLS 1.2+) /api/v1/…
                         ▼
            ┌──────────────────────────────────────────┐
            │  Django app (WSGI: gunicorn / uvicorn)   │
            │  + DRF APIView  ·  DRF Spectacular        │
            │  Auth: apps.accounts.auth.MFATokenAuth    │
            └────┬───────────────┬──────────────┬───────┘
                 │               │              │
                 ▼               ▼              ▼
          ┌──────────┐   ┌────────────┐   ┌──────────┐
          │ PostgreSQL│   │   Redis    │   │  Celery  │  (workers + django-
          │ (records, │   │ (broker +  │   │  beat    │   celery-beat; tasks)
          │  audit,   │   │  channels) │   │          │
          │  billing)│   └───────────┘  └──────────┘
          └──────────┘
                 │
            ┌────▼─────────────────────────────────┐
            │  Quarantine dir (QUARANTINE_DIR)     │  on-disk; admin only
            └──────────────────────────────────────┘

           Egress:        ┌────────┐  HTTPS  ┌──────────────┐
          LLM calls ───►  │  LLM   │        │ OpenAI-style │
          Safepay ──────► │ gateway│        │  /Safepay    │
          Email ────────► │  SMTP  │        │ SES/SendGrid │
```

## 2. Data stores

| Store | Purpose | Secrets | Notes |
|-------|---------|---------|-------|
| **PostgreSQL** (`DATABASE_URL`) | `User`, `ScanRecord`, `Alert`, `LLMInteraction`, `Subscription`, `BillingEvent`, `ScheduledScan`, `Incident`/`QuarantineItem` registry, `AuditLogEntry`, `django-otp`/`two_factor`, `django_celery_beat` | `SAFEPAY_SECRET_KEY`, `SAFEPAY_WEBHOOK_SECRET`, `ENCRYPTION_MASTER_KEY`, JWT signing secret | Primary store. Default local URL is Postgres; SQLite is dev/test only. |
| **Redis** (`REDIS_URL`, default `redis://localhost:6379/0`) | Celery broker + result backend (`rpc`) + Channels layer | none (localhost) | External only if `REDIS_URL` points elsewhere. |
| **Quarantine directory** (`QUARANTINE_DIR`, default `<MEDIA_ROOT>/quarantine`) | Quarantined uploaded/payload bytes + sidecar JSON metadata | none | Filesystem; path-traversal-safe (`name == Path(name).name`). |
| **SQLite** (`sqlite:///…`) | Dev/test only | test-only keys | Never production. |
| **Env / process memory** | `ENCRYPTION_MASTER_KEY`, JWT secret, `LLM_API_KEY`, Safepay secrets | all | Injected via env / `.env`; never committed. |

### At-rest encryption (KMS abstraction)

`mycyber/services/kms.py` exposes an `EnvVarKMS` backend (default, dev/test)
with a pluggable interface so a real KMS (AWS/GCP) can be dropped in without
changing application code. Field-level helpers in
`mycyber/services/field_encryption.py` encrypt sensitive columns with
**AES-256-GCM** using a per-field data key derived via **HKDF-SHA256** over the
master key (16-byte salt, 12-byte nonce, 16-byte tag; format
`v1:<b64(salt)>:<b64(nonce)>:<b64(ct|tag)>`). Registered sensitive fields:

- `accounts.User.mfa_secret`
- `billing.Subscription.safepay_token`, `billing.Subscription.safepay_tracker`
- `billing.BillingEvent.safepay_data`

`reencrypt_all_sensitive_fields()` rotates every registered field under the
current key version (`ENCRYPTION_KEY_VERSION`) and is wired into
`AccountsConfig.ready()`.

### Passwords & MFA

- Passwords are stored with **bcrypt (12 rounds)** in production; tests use
  `MD5PasswordHasher` for speed. Django's `set_password`/`check_password` are
  used (the `password` column, **not** `hashed_password`).
- MFA: TOTP secrets are encrypted at rest and verified via
  `mycyber/services/mfa.py`. Two-factor-auth (`django-two-factor-auth` +
  `django-otp`) protects the **Django admin UI**; API-level MFA is enforced by
  `MFATokenAuthentication` with the `MFA_ROLLOUT_MODE` (off|opt_in|enforced).

## 3. Request processing & auth

```
HTTP request
  → django-prometheus (metrics)
  → corsheaders
  → SecurityMiddleware → Session → Common → CSRF → Auth → OTP/TwoFactor → Messages
  → RequestIdMiddleware (request_id)
  → ActorMiddleware (audit actor)
  → Django REST Framework
        Authentication: MFATokenAuthentication (PyJWT HS256)
        Permission: IsAuthenticated (+ IsAdminRole / IsAnalystRole via RBAC)
        View → Service → Model → AuditLogEntry (append-only)
```

- **Tokens** are signed with **PyJWT** (HS256) and carry `sub`/`email`/
  `tenant_id`/`iat`/`exp` — identical to the FastAPI contract, so the frontend's
  `VITE_API_URL` and token shape are unchanged. `djangorestframework-simplejwt`
  is installed but **not** used for issuing tokens (kept only for schema/admin).
- **Session timeout**: a token whose `iat` is older than `SESSION_TIMEOUT_HOURS`
  (default 24h) is rejected with **HTTP 419** after an `session_expired` audit
  entry is written. `exp` is also verified (`AuthError` → 419/401).
- **RBAC**: `_ROLE_HIERARCHY = {viewer:0, analyst:1, admin:2}` in
  `mycyber/services/auth.py`; `resolve_role` returns `admin` for superusers.
  `/admin/*` endpoints require `IsAdminRole` (403 otherwise).
- **Rate limiting**: the FastAPI `check_rate_limit` service was intentionally
  **not** ported to `django-ratelimit` (locmem cache is not shared across
  workers → E003). DRF `AnonRateThrottle`/`UserRateThrottle` provide per-process
  coarse limits; per-user Redis throttling is the FastAPI path.
- **`django-import-export`**, `django-silk`, `django-prometheus`** are wired for
  the admin UI and metrics but hold no secrets.

## 4. Audit & immutability

`apps.audit.AuditLogEntry` is the tamper-evident record. Every scan, alert,
admin action, login, MFA, password-reset, LLM interaction, plan change, and
session-expiry is written by `mycyber/services/audit_log.py`:

- Append-only: `append_audit_log` never `UPDATE`s or `DELETE`s.
- Hash chaining: `previous_hash` = HMAC-SHA256 of the prior entry's
  `entry_hash`; the first row uses sentinel `GENESIS`. Each entry's
  `entry_hash` is HMAC-SHA256 keyed on `SAFEPAY_SECRET_KEY` (falls back to the
  JWT secret) over a canonical `|` payload of its fields.
- Verification: `verify_chain(tenant_id)` walks the chain in order and reports
  any break/hash mismatch. Exposed at `GET /api/v1/admin/audit/verify`.
- Export: `export_audit_log` (filterable, paginated) and CSV export,
  both admin-only.

## 5. Egress surfaces & controls

| Destination | Trigger | Auth | Controls |
|-------------|--------|------|----------|
| **OpenAI-compatible LLM** (`LLM_BASE_URL`) | `POST /api/v1/llm-dlp/chat` → `call_llm_api` | Bearer JWT | HTTPS enforced at startup (`_validate_llm_url`); bearer key from `LLM_API_KEY`; `DEPLOYMENT_REGION=PK` blocks all external LLM calls (503); prompts are pre-scanned, redacted, and post-scanned for leaks; leaked keys are logged to `auto_deactivate_keys` + alert + `EVENT_LLM_INTERACTION` audit entry. |
| **Safepay** (checkout + webhook) | `POST /billing/upgrade`, `POST /billing/webhook` | upgrade→JWT; webhook→none (public) | Checkout via `X-SFPY-MERCHANT-SECRET`; webhook verifies `HMAC-SHA256(payload, SAFEPAY_WEBHOOK_SECRET)` and rejects bad signatures with 400 immediately. |
| **Email** (SMTP/SendGrid) | password reset, alert notifications | n/a | Dev uses locmem; prod uses `EMAIL_FROM`. No secrets in message bodies. |
| **Redis** | Celery + Channels | n/a | `REDIS_URL`; defaults to localhost. |
| **Filesystem (quarantine)** | `POST /admin/quarantine/quarantine`, scan file upload | admin JWT | Path-traversal guard (`name == Path(name).name`); bytes stored under `QUARANTINE_DIR`. |

No egress is performed without an explicit secret or configuration variable.
The DLP scan engine is **regex-only by default** (import-safe; `transformers`/
`PIL`/`pdfplumber`/`python-docx`/`pytesseract`/`tika` are lazy and optional).

## 6. Secrets handling

- All secrets are **injected via environment variables** (`DJANGO_SECRET_KEY`,
  `JWT_SECRET_KEY`, `ENCRYPTION_MASTER_KEY`, `SAFEPAY_SECRET_KEY`,
  `SAFEPAY_WEBHOOK_SECRET`, `LLM_API_KEY`) — never committed. `conf.py` reads
  them at call-time so test overrides are honoured.
- Safepay tokens/trackers and LLM prompts are **encrypted at rest** via the KMS
  helpers (see §2). The `reencrypt_all_sensitive_fields` rotation job runs on
  app ready and is exercised by `test_reencrypt_all_sensitive_fields`.
- JWT signing keys are never logged; `call_llm_api` logs only non-secret
  metadata (status codes, truncated error text).
- `SECURITY_HEADERS` / `CSRF`/clickjacking middleware are enabled (production
  turns on HSTS via `SecurityMiddleware` when `SECURE_SSL_REDIRECT`).

## 7. Threat notes & mitigations

- **Secret leakage in LLM prompts/responses**: mitigated by pre-scan → redact →
  LLM → post-scan → auto-deactivate + alert + audit (§5).
- **Audit tampering**: HMAC-SHA256 hash chain keyed off a server-side secret the
  DB alone does not hold; `verify_chain` detects reordering, deletion, or field
  mutation.
- **SQLi/XSS in scan reports**: CSV/HTML exports escape all cell content
  (`html.escape` in `export_html`); report endpoints are auth-scoped to the
  requesting tenant.
- **Directory traversal in quarantine**: enforced in `quarantine_dir()`/`_safe_path`.
- **CSRF**: API is JWT-bearer (no cookie session), so CSRF is not in scope for
  API endpoints; CSRF middleware remains for the admin UI which uses sessions.
- **Denial of service**: per-user Redis `check_rate_limit` (FastAPI path) and
  DRF throttles bound request rates; plan limits (`check_plan_limit` → 429) bound
  monthly scans.
