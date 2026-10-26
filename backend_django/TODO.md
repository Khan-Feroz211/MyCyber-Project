# TODO — Django Migration (`backend_django/`)

> Scope derived from the project root `TODO.md` (Tomorrow's Work). This file tracks
> progress porting the existing FastAPI backend (`backend/`) onto the new Django
> + Django REST Framework + Celery stack in `backend_django/`.

## Status Legend
- `[ ]` todo / in-progress
- `[x]` done

---

## Phase 0 — Make the Django project runnable (BLOCKER)
The settings/urls/celery modules are already written but reference app code that
does not exist yet. Until these resolve, `manage.py check` and tests cannot run.

- [x] Remove `django_celery_results` from `INSTALLED_APPS` (not installed in venv) — `celery.py`
      `CELERY_RESULT_BACKEND = "django-db"` points at it. Switched backend to `rpc`/`cache`
      for now; revisit when the package is added.
- [x] Create `mycyber/logging.py` (`JSONFormatter`) — referenced by dev/prod logging config.
- [x] Create `mycyber/middleware/request_id.py` (`RequestIdMiddleware`) — referenced in MIDDLEWARE.
- [x] Create `mycyber/middleware/audit.py` (`ActorMiddleware`) — referenced in MIDDLEWARE.
- [x] Create `mycyber/admin_urls.py` — referenced by `urls.py` (`include("mycyber.admin_urls")`).
- [x] Add `apps.py` (`AppConfig`) for every local app so Django discovers them cleanly.
- [x] Create stub `urls.py` for `dlp`, `llm`, `alerts`, `billing`, `scheduling`,
      `incidents` so `mycyber.urls` imports resolve.
- [x] Create `apps/scans/tasks.py` (Celery task module) — imported by `celery.py`.
- [x] Create `apps/alerts/routing.py` (`websocket_urlpatterns`) — imported by `asgi.py`.
- [x] `manage.py check` passes with an empty SQLite DB.

## Phase 1 — Shared security services (ported from `backend/app/services/`)
- [x] `mycyber/services/kms.py` — `EnvVarKMS`, `encrypt_field`/`decrypt_field`/`reencrypt_field`,
      AES-256-GCM, key-version rotation, `get_encryption_status`.
- [x] `mycyber/services/field_encryption.py` — MFA-secret / payment-token / safepay-data /
      LLM-prompt field helpers + `reencrypt_all_sensitive_fields` job.
- [x] `mycyber/services/mfa.py` — TOTP secret gen + verify (port of `backend/app/services/mfa.py`).
- [x] `mycyber/services/security_audit.py` — `log_security_event` for `SecurityAuditEvent`.
- [x] `mycyber/services/auth.py` — `hash_password`/`verify_password` (bcrypt 12 / MD5 test),
      `create_access_token`/`decode_access_token`, refresh + reset tokens, session-timeout check
      (419 re-auth), RBAC role hierarchy.
- [x] `mycyber/services/email_service.py` — SMTP/SendGrid password-reset mail (dev fallback).
- [x] `mycyber/services/audit_log.py` — hash-chained `append_audit_log`/`verify_chain`/`export_audit_log` (consolidated into shared services pkg).

## Phase 2 — `apps.accounts` (foundation auth feature)
- [x] `User` custom model (email PK/unique, tenant_id, role, plan, MFA fields, RBAC) + `UserManager`.
- [x] Django admin registration (`apps/accounts/admin.py`).
- [x] DRF serializers (`UserCreate`, `UserOut`, `Token`, MFA/reset schemas, admin action payloads).
- [x] JWT auth: `apps/accounts/auth.py` (`MFATokenAuthentication`, session-timeout 419).
- [x] Views: `register`, `login`, `me`, `me/full`, `session`, `mfa/status`, `mfa/setup`,
      `mfa/verify`, `mfa/disable`, `password/reset/request`, `password/reset/confirm`.
- [x] `views/health.py` → `healthz`.
- [x] `urls.py` + `urls_admin.py`.

## Phase 3 — `apps.audit` (immutable hash-chained audit log)
- [x] Models: `AuditLogEntry` (hash-chained) + `SecurityAuditEvent`.
- [x] Service: `append_audit_log`, `verify_chain`, `export_audit_log`.
- [x] Views (admin-only): `export` (JSON), `export/csv`, `verify`.
- [x] `urls.py`.
- [x] Wire `admin/security` (`apps.accounts.urls_admin`) → incident list + user lock/unlock/
      deactivate/reactivate + encryption status/rotate endpoints.

## Phase 4 — Tests (mirrors `backend/tests/`)
- [x] `mycyber/settings/test.py` (SQLite :memory:, test env vars, MD5 hashers, locmem email, eager celery).
- [x] `tests/` package + `tests/helpers.py` (Django `APIClient`, admin/user helpers, auth headers).
- [x] `tests/test_kms_encryption.py` — KMS backend, field encrypt/decrypt round-trip, key rotation.
- [x] `tests/test_audit_log.py` — append/hash-chaining/verify/export + HTTP 403/200 RBAC.
- [x] `tests/test_rbac.py` — role gating on admin endpoints, session-timeout 419.
- [x] `tests/test_auth.py` — register/login/me/protected.

> **Status (achieved):** `manage.py check` = 0 issues; `manage.py makemigrations --check` = no drift; `manage.py test` = **45 tests, OK**.
> Run: `cd backend_django && .venv-django\Scripts\python manage.py test --settings=myzcyber.settings.test` (note: `--settings=myzcyber.settings.test`).

## Phase 5 — Remaining apps (port from FastAPI routers)
- [x] `apps.scans` (dlp) — regex-only, import-safe scanner engine
      (`mycyber/services/scanner.py`); text/file/network scan + history/detail/stats/models +
      `scan_and_persist` (save_scan + `EVENT_SCAN` audit + plan-limit gate).
- [x] `apps.alerts` — alert list/acknowledge-all/count/review/delete/detail + WebSocket
      routing (channels) stub in `routing.py`.
- [x] `apps.llm` — LLP DLP pipeline (`run_llm_dlp_pipeline`); chat/history/detail/stats
      views. External `httpx` LLM call is lazy/guarded (503 without `LLM_API_KEY`).
- [x] `apps.incidents` — reports export (CSV/HTML/JSON + printable PDF-ready HTML) +
      file-system quarantine (list/get/release/download/delete/upload).
- [x] `apps.billing` — plans, usage, Safepay checkout (lazy `httpx`, 502 on gateway error),
      webhook HMAC verification + payment succeeded/failed/cancelled handlers; token/tracker
      encryption at rest; sensitive-field rotation registration.
- [x] `apps.scheduling` — scheduled-scan CRUD + run-now + Celery beat
      `run_scheduled_scan` task.
- [x] All new models migrated (`makemigrations --check` = no drift); `manage.py check` = 0 issues.
- [x] `tests/test_scan.py` — scan→alert→audit end-to-end smoke (text/file-safe, credit-card
      alert, audit hash-chain valid, history, stats, auth enforcement, alert ack, billing
      plans public, LLM history/stats, scheduling CRUD).

> **Status (Phase 5):** `manage.py check` = 0 issues; `manage.py makemigrations --check` = no
> drift; `manage.py test` = **57 tests, OK** (45 Phase 0–4 + 12 Phase 5).

## Phase 6 — k6 load test + docs (mirrors project TODO.md)
- [x] `tests/load/README.md` with measured RPS against the Django stack (k6 script + stdlib `bench_scan.py` benchmark; numbers recorded for safe/risky scan + read-only baseline, with sqlite vs Postgres notes).
- [x] `SECURITY_ARCHITECTURE.md` (Django data stores: Postgres/Rabbit/Redis, processing, egress, secrets, threat notes).
- [x] `docs/compliance/` SOC2 + ISO27001 control mapping (with code/test evidence references).
- [x] README "Security & Compliance" section for the Django backend (`backend_django/README.md`).
