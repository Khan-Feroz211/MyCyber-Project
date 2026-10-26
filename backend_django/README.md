# MyCyber DLP — Django backend

The Django + Django REST Framework port of the MyCyber DLP service
(originally `backend/`, FastAPI). It exposes the same `/api/v1/*` contract as
the FastAPI backend so the React/Vite frontend (`VITE_API_URL`) works with no
client changes.

## Quick start

```bat
set DATABASE_URL=sqlite:///./dev.db
set DJANGO_SECRET_KEY=django-dev-secret-key-32ch!
set JWT_SECRET_KEY=jwt-test-secret-key-32bytes!!
set ENCRYPTION_MASTER_KEY=test-encryption-key-32-bytes-long!!!

backend_django/manage.py migrate --settings=mycyber.settings.dev --no-input
backend_django/manage.py runserver 127.0.0.1:8000 --settings=mycyber.settings.dev
```

API: `http://127.0.0.1:8000/api/v1/` · OpenAPI: `http://127.0.0.1:8000/api/docs/`

## Test suite

Tests are Django `TestCase` + `rest_framework.test.APIClient` (pytest is **not**
used). Run from the project root:

```bat
set DATABASE_URL=sqlite:///./test.db
set DJANGO_SECRET_KEY=test-django-secret-key-for-pytest-only-32ch!
set JWT_SECRET_KEY=test-jwt-secret-key-for-pytest-only-32chars!
set ENCRYPTION_MASTER_KEY=test-encryption-key-32-bytes-long!!!

backend_django/manage.py test tests.test_auth tests.test_audit_log tests.test_kms_encryption tests.test_rbac tests.test_scan --settings=mycyber.settings.test
```

`mycyber.settings.test` is hermetic (SQLite `:memory:`, locmem email/cache, MD5
hashers, eager Celery) — no Postgres/Redis/SendGrid/LLM keys required.

## Project layout

```
backend_django/
├── manage.py
├── mycyber/                  # project: settings (base/dev/prod/test/bench), urls, celery, middleware, logging, admin_urls
├── mycyber/services/         # shared services: conf, kms, field_encryption, mfa, auth,
│                              # scanner (regex DLP engine), audit_log, email_service, security_audit
├── apps/
│   ├── accounts/             # User model, MFA, RBAC, JWT auth, admin security views
│   ├── audit/                # hash-chained AuditLogEntry + SecurityAuditEvent
│   ├── dlp/                  # scan HTTP views (text/file/network/history/stats)
│   ├── scans/                # ScanRecord model + scan Store service
│   ├── alerts/               # Alert model + list/ack/review/delete views
│   ├── incidents/            # Incident model + reports (CSV/HTML/JSON) + quarantine
│   ├── llm/                  # LLMInteraction + run_llm_dlp_pipeline (redact→LLM→post-scan)
│   ├── billing/              # Subscription/BillingEvent + Safepay checkout/webhook
│   └── scheduling/           # ScheduledScan + Celery beat task
├── tests/
│   ├── helpers.py            # APIClient auth helpers
│   ├── test_auth.py / test_audit_log.py / test_kms_encryption.py / test_rbac.py
│   ├── test_scan.py          # Phase 5 scan→alert→audit smoke tests
│   └── load/                 # k6 script + stdlib benchmark + measured RPS README
├── SECURITY_ARCHITECTURE.md
└── docs/
    └── compliance/           # SOC 2 + ISO 27001 control mapping
```

## Security & Compliance

- **Authn/authz**: PyJWT HS256 access tokens (`sub/email/tenant_id/iat/exp`),
  24-hour session timeout (HTTP 419), bcrypt passwords, TOTP MFA. See
  `apps.accounts.auth` + `mycyber.services.auth`.
- **RBAC**: `viewer` / `analyst` / `admin` roles; admin endpoints gated by
  `IsAdminRole` (403 otherwise).
- **Encryption at rest**: AES-256-GCM field encryption (`mycyber.services.kms`,
  `mycyber.services.field_encryption`) for MFA secrets, Safepay tokens/trackers
  and LLM prompts; key-version rotation job.
- **Audit**: immutable, hash-chained `AuditLogEntry` (HMAC-SHA256, keyed off
  `SAFEPAY_SECRET_KEY`/JWT secret); `verify_chain()` for tamper detection.
- **DLP**: regex-only, import-safe scanner engine (lazy NER/transformers/PIL);
  LLM pipeline pre-scans, redacts, calls HTTPS-only LLM, post-scans, and
  auto-logs/deactivates leaked keys + raises an alert + audit event.
- **Secrets**: all secrets are environment-injected (`DJANGO_SECRET_KEY`,
  `JWT_SECRET_KEY`, `ENCRYPTION_MASTER_KEY`, `SAFEPAY_*`, `LLM_API_KEY`); none
  are committed.
- **Egress controls**: HTTPS-only LLM egress; `DEPLOYMENT_REGION=PK` blocks
  external LLM calls; Safepay webhooks verified by HMAC-SHA256.
- **Compliance artefacts**: see [`SECURITY_ARCHITECTURE.md`](SECURITY_ARCHITECTURE.md)
  and [`docs/compliance/`](docs/compliance/). The
  [`docs/compliance/SOC2_ISO27001_mapping.md`](docs/compliance/SOC2_ISO27001_mapping.md)
  maps implemented controls to SOC 2 (TSC 2017) and ISO/IEC 27001:2022 Annex A
  with code/test evidence.
- **Load testing**: `tests/load/README.md` documents a reproducible benchmark
  with measured RPS (see that file for the numbers and how to reproduce with
  k6 or the bundled stdlib benchmark).

## Edge cases & troubleshooting

> If something "just hangs" or returns 401/403/419, it is almost one of these.

- **PostgreSQL hangs on connect.** The default `DATABASE_URL` is
  `postgresql://postgres:postgres@localhost:5432/mycyber_dlp`, which will hang
  if no Postgres is running. Always override it with a real SQLite file for
  local work: `set DATABASE_URL=sqlite:///./dev.db` (for `runserver`/`migrate`)
  or `sqlite:///./bench.db` (for benchmarks). Never point a single-process dev
  server at Postgres you don't have.
- **`manage.py test` from the *repo root* errors on `import app`.** Discovery
  picks up the legacy FastAPI test files (`test_registration.py` etc.) at the
  repo root, which `import app` (needs `aiofiles`, not installed) and explode.
  **Always** run from the project root and pass explicit labels:
  `backend_django/manage.py test tests.test_auth tests.test_scan …`.
- **401 on every request with the dev server.** `mycyber.settings.dev` puts
  `simplejwt` authentication first; the React/Vite frontend issues PyJWT HS256
  tokens directly, so `simplejwt` rejects them (401) before our auth runs. Use
  the **bench** settings instead, which keep MFA-only PyJWT auth:
  `manage.py runserver 127.0.0.1:8123 --noreload --settings=mycyber.settings.bench`.
- **Tables missing across processes with `:memory:` SQLite.** The `test` setting
  hardcodes `NAME=":memory:"` per-connection, so `migrate` and `runserver` get
  *different* in-memory DBs. Use a **file** DB (`sqlite:///./bench.db`) when
  running a live server, or rely on Django's test DB auto-creation via
  `manage.py test`.
- **`--threaded` is rejected.** Django's dev server is threaded by default;
  passing `--threaded` raises an unrecognized-argument error. Drop the flag.
- **419 = session expired (24h).** A 419 from any view means the bearer token
  is older than `SESSION_TIMEOUT_HOURS` (default 24). Re-login. 403 = logged-in
  but not an admin (RBAC). 401 = bad/expired signature.
- **Plan quota: 429 Too Many Requests.** `free`=100, `pro`=10,000,
  `enterprise`=999,999 scans/month. The scan view calls `check_plan_limit`
  before scanning, so the first scan of the next month resets the counter.
- **MFA locked out.** `MFA_ROLLOUT_MODE` defaults to `opt_in`. If a user loses
  their device and `MFA_FORCE` is not set, an admin can reset via the admin
  security views (`/admin/…`) or toggle MFA off for the tenant.
- **SafePay webhook signature mismatch.** Verify `SAFEPAY_WEBHOOK_SECRET` is
  set to the *same* value configured in the SafePay dashboard; the view HMACs
  the raw body (no JSON re-serialization). Tampered timestamps >5 min are
  rejected.
- **`verify_chain()` reports a break at a tenant boundary.** Audit chaining is
  **per-tenant**: each tenant's first entry anchors `previous_hash=GENESIS`.
  `verify_chain()` with no argument walks *all* entries globally and is only
  valid in a **single-tenant** DB. Use `verify_chain(tenant_id=<id>)` for a
  specific tenant. System-level actions (no tenant) use the reserved tenant
  `"system"`; they chain off that tenant's `GENESIS`.
- **Purge deletes the right rows, never the audit log.**
  `python manage.py purge_old_data --days 30` removes stale scans/alerts/LLM /
  incidents/quarantine older than `DATA_RETENTION_DAYS` (default 365) but
  **never** touches `AuditLogEntry`. Pass `--tenant <id>` to scope the purge and
  its audit entry to one tenant.
- **Field encryption key rotation.** `ENCRYPTION_MASTER_KEY` rotation is done
  via `mycyber.services.kms` (`reencrypt_all_sensitive_fields`); sensitive
  fields are registered per-app in each `AppConfig.ready()` via
  `register_sensitive_field`. The format is
  `v1:<b64(salt)>:<b64(nonce)>:<b64(ct+tag)>` with an HKDF-derived data key.

