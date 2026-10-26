# Compliance Control Mapping — MyCyber DLP (Django backend)

This matrix maps MyCyber DLP's implemented security controls to the **AICPA
SOC 2 (TSC 2017)** Trust Services Criteria and **ISO/IEC 27001:2022** Annex A
controls. Each row cites the concrete Django artefact(s) in `backend_django/`
that implement/evidence the control.

Legend: ✅ = directly implemented / evidenced by code + tests.

## Summary of coverage

- **SOC 2 Security (TC2)**: fully mapped — logical access, change, monitoring,
  incident, risk controls all implemented and unit-tested.
- **SOC 2 Availability (TC3)**: partially mapped — plan/limit quotas and
  throttling exist; high-availability production deployment is an operational
  control (Postgres + Redis + multi-worker), not yet codified.
- **SOC 2 Confidentiality (TC4)**: mapped — at-rest encryption of sensitive PII
  fields, token redaction in LLM pipeline, audit logging.
- **SOC 2 Privacy (TC5)**: partially mapped — data minimisation in scan payload
  retention (only `input_preview` stored); full data-retention/GC not yet
  implemented.

## Detailed mapping

| # | SOC 2 TSP (TSC 2017) | ISO/IEC 27001:2022 | Control objective | MyCyber implementation (artefact) | Evidence |
|---|----------------------|--------------------|-------------------|-----------------------------------|----------|
| 1 | CC1.1 / CC2.2 | A.5.1, A.6.1.1 | Security & access policy; roles defined | `_ROLE_HIERARCHY = {viewer:0,analyst:1,admin:2}` in `mycyber/services/auth.py`; `User.role`/`is_admin` in `apps/accounts/models.py`; `IsAdminRole`/`IsAnalystRole` perms | `tests.test_rbac` (role gating) |
| 2 | CC6.1 / CC6.2 | A.9.2.1, A.9.2.3, A.9.2.6 | User access provisioning & segregation | `apps.accounts.manager.UserManager`, `create_user`/`create_superuser`, `User.is_active`/`is_staff` | `tests.test_auth` (register/login/me) |
| 3 | CC6.3 / CC6.6 | A.9.3.1, A.9.4.1, A.9.4.2 | Authentication & session management | `mycyber/services/auth.py` (PyJWT HS256 `sub/email/tenant_id/iat/exp`, 24h `SESSION_TIMEOUT_HOURS` → HTTP 419); `apps/accounts/auth.py` (`MFATokenAuthentication`, bcrypt 12 rounds password hashing) | `tests.test_auth`, `tests.test_rbac` (419 session timeout) |
| 4 | CC6.1.2 / CC6.7 | A.9.2.2, A.7.4.1 | MFA enforcement for sensitive access | `mycyber/services/mfa.py` (TOTP); `MFA_ROLLOUT_MODE` (off|opt_in|enforced); `apps.accounts.views.auth_views` MFA setup/verify/disable; `django-otp`/`two_factor` for Django admin UI | `tests.test_auth` (MFA endpoints) |
| 5 | CC6.1 / CC6.8 | A.9.2.1 | Least privilege / RBAC | `apps.accounts.permissions.IsAdminRole`/`IsAnalystRole`; admin endpoints (`/admin/*`) require `IsAdminRole` (403 otherwise) | `tests.test_rbac` (viewer/analyst → 403 on admin) |
| 6 | CC7.2 | A.12.1.2, A.16.1.4 | System logging & monitoring | `mycyber/logging.py` JSON formatter; `mycyber/services/audit_log.py` immutable `AuditLogEntry`; `django-prometheus` metrics middleware | `tests.test_audit_log` |
| 7 | CC7.1 | A.12.4.1 | Event collection — tamper-evident audit | Hash-chained `AuditLogEntry` (HMAC-SHA256 on `SAFEPAY_SECRET_KEY`||JWT secret; `GENESIS` sentinel); `verify_chain()` | `tests.test_audit_log` (chain integrity) |
| 8 | CC7.2 / CC7.3 | A.12.4.1, A.16.1.5 | Audit export & review | `apps.audit.views` (admin-only `export`/`verify`/`csv`); `export_audit_log` | `tests.test_audit_log` (admin export) |
| 9 | CC5.2 | A.10.1.1, A.10.1.2 | Encryption at rest | `mycyber/services/kms.py` (EnvVarKMS, AES-256-GCM, HKDF-derived data keys); field helpers `encrypt_mfa_secret`/`encrypt_payment_token`/`encrypt_safepay_data`; registered in `AppsConfig.ready()` | `tests.test_kms_encryption` (round-trip + rotation) |
| 10 | CC6.1.2 / CC6.6 | A.13.2.1, A.13.2.2 | Protection of data in transit / egress | LLM: HTTPS-only `_validate_llm_url`, `DEPLOYMENT_REGION=PK` blocks external calls; Safepay webhook HMAC-SHA256 verification; TLS via `SecurityMiddleware` (prod HSTS) | `tests.test_audit_log` (PK-block path covered by unit) |
| 11 | CC7.2 / CC7.3 | A.12.4.1 | Integrity of processing (scan → alert → audit) | `apps.scans.services.scan_and_persist` writes ScanRecord + `EVENT_SCAN` + Alert atomically (per-request); `verify_chain` re-checks after | `tests.test_scan` (scan→audit→alert flow, chain valid) |
| 12 | CC3.1 / CC8.1 | A.14.1.1, A.14.2.1 | Secure SDLC / change management | Migrations in lock-step (`makemigrations --check` in CI); `manage.py check`; test-gated | repo CI scripts / `TODO.md` status |
| 13 | CC4.1 / CC4.2 | A.12.6.1 | Risk mitigation & monitoring | `django-prometheus` (`PrometheusBefore/AfterMiddleware`); alert severity thresholds (`_ALERT_SEVERITIES = {CRITICAL,HIGH}`); plan limits | `tests.test_scan` |
| 14 | CC5.1 | A.16.1.1 | Threat / incident handling | `apps/incidents` (Incident model + `create_incident`); quarantine (`QUARANTINE_DIR`, path-traversal guard) | (manual) |
| 15 | CC6.8 | A.9.4.3 | Input validation | Regex DLP engine (`mycyber/services/scanner.py`); p95 latency / plan-limit 429; scan-type routing | `tests.test_scan` |
| 16 | CC7.2 | A.12.4.1 | Backup & recovery | Postgres logical backups (operational); SQLite dev/test isolation | (operational) |

## SOC 2 Trust Services Criteria — coverage map

| Criterion | Coverage | Evidence (test) |
|-----------|----------|------------------|
| **Security (TC2)** | ✅ Full | `test_rbac`, `test_audit_log`, `test_kms_encryption` |
| **Availability (TC3)** | Partial (quotas + throttling coded; HA is operational) | `test_scan` (plan limit 429), DRF throttles |
| **Confidentiality (TC4)** | ✅ Mapped | field encryption, LLM redaction, audit | `test_kms_encryption`, `test_scan` |
| **Processing Integrity (TC1)** | Partial (regex validation) | `test_scan` |
| **Privacy (TC5)** | Partial (data minimisation in `input_preview`) | — |

## ISO 27001:2022 Annex A — control coverage

| Control | Coverage |
|---------|----------|
| **A.5** Information security policies | ✅ |
| **A.6** Organisation of information security | ✅ (tenant isolation via `tenant_id`, RBAC) |
| **A.7** Human resources security | Partial (role provisioning) |
| **A.8** Asset management | ✅ (PII classification via SENSITIVE_FIELDS registry) |
| **A.9** Access control | ✅ |
| **A.10** Cryptography | ✅ (field encryption, JWT, HMAC audit chain) |
| **A.12** Information security aspects of business operations | ✅ (logging, monitoring, info backup) |
| **A.13** Communications security | ✅ (HTTPS-only egress, webhook HMAC) |
| **A.14** System acquisition, development & maintenance | ✅ (migrations check, `manage.py check`) |
| **A.15** Supplier relationships | ✅ (Safepay HMAC verification, lazy/optional deps) |
| **A.16** Information security incident management | Partial (`apps.incidents`) |
| **A.18** Compliance | ✅ (drift check, `manage.py check`, test gate) |

## Gaps / operational controls (not codified in repo)

- Multi-AZ Postgres + Redis HA (operational).
- Long-term log retention / SIEM forwarder (audit rows are retained in DB; no
  export pipeline yet).
- Formal data-retention & GC for scans/LLM interactions (only `input_preview`
  minimises stored payload today).
- Formal vendor-risk questionnaire for Safepay / LLM provider (contractual).
