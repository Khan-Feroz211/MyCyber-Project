# Security, Backup, Restore, and Secrets Hardening Checklist

## 1. MFA Rollout (Phased)
- Set `MFA_ROLLOUT_MODE=off` for initial deployment validation.
- Set `MFA_ROLLOUT_MODE=opt_in` to enforce MFA only for users with enabled TOTP.
- Set `MFA_ROLLOUT_MODE=enforced` for full MFA enforcement.
- Verify `/api/v1/auth/mfa/setup`, `/api/v1/auth/mfa/verify`, and `/api/v1/auth/mfa/status`.

## 2. Account Lockout and Suspicious Login
- Configure `LOGIN_MAX_FAILURES` and `LOGIN_LOCK_MINUTES` in environment.
- Confirm lockout triggers after repeated bad credentials.
- Confirm suspicious login event generation on login from a new IP.
- Review incidents in `/api/v1/admin/security/incidents` as an admin user.

## 3. Security Audit Event Pipeline
- Ensure migration `006_add_auth_security_and_audit_events.py` is applied.
- Confirm events are persisted for:
  - `login_failed`
  - `login_success`
  - `suspicious_login_new_ip`
  - `mfa_failed` / `mfa_enabled` / `mfa_disabled`
  - admin response actions

## 4. Incident Response Actions
- Use admin endpoints to contain compromised accounts:
  - `POST /api/v1/admin/security/respond/lock-user`
  - `POST /api/v1/admin/security/respond/unlock-user`
  - `POST /api/v1/admin/security/respond/deactivate-user`
  - `POST /api/v1/admin/security/respond/reactivate-user`
- Document every response action reason.

## 5. Backup and Restore Operations
- Daily DB backup command:
  - `pg_dump -Fc -h <db-host> -U <db-user> -d mycyber_dlp > backup.dump`
- Restore command:
  - `pg_restore -h <db-host> -U <db-user> -d mycyber_dlp --clean --if-exists backup.dump`
- Perform quarterly restore drills in non-production.
- Keep at least one immutable off-site encrypted backup.

## 6. Secrets Hardening
- Rotate JWT, DB, SMTP, and billing secrets regularly.
- Do not commit `.env`, `.env.docker`, or runtime secrets.
- Use managed secret stores in production (Azure Key Vault, AWS Secrets Manager, or HashiCorp Vault).
- Set strict file permissions for secret material and key files.
- Audit service accounts for minimum required privilege.

## 7. Validation Before Release
- Run backend tests and smoke auth flows.
- Validate admin incidents dashboard access controls.
- Verify that non-admin users cannot call admin security actions.
- Confirm health endpoint and primary login flows after migration.
