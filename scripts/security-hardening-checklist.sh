#!/usr/bin/env bash
set -euo pipefail

# MyCyber security readiness helper.
# This script validates key environment toggles and prints backup/restore commands.

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="${ROOT_DIR}/.env.docker"

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "[WARN] .env.docker not found at ${ENV_FILE}"
  echo "Create it from .env.docker.example before production deployment."
else
  echo "[INFO] Found .env.docker"
fi

echo ""
echo "=== Required security configuration ==="
for key in MFA_ROLLOUT_MODE LOGIN_MAX_FAILURES LOGIN_LOCK_MINUTES JWT_SECRET_KEY; do
  if grep -q "^${key}=" "${ENV_FILE}" 2>/dev/null; then
    value="$(grep "^${key}=" "${ENV_FILE}" | tail -n1 | cut -d'=' -f2-)"
    echo "[OK] ${key}=${value}"
  else
    echo "[MISSING] ${key}"
  fi
done

echo ""
echo "=== Backup command (PostgreSQL) ==="
echo "pg_dump -Fc -h <db-host> -U <db-user> -d mycyber_dlp > backup.dump"

echo ""
echo "=== Restore command (PostgreSQL) ==="
echo "pg_restore -h <db-host> -U <db-user> -d mycyber_dlp --clean --if-exists backup.dump"

echo ""
echo "=== Secrets hardening checks ==="
echo "- Ensure .env* files are excluded from source control"
echo "- Rotate JWT/DB/SMTP/Safepay credentials"
echo "- Restrict permissions on key and secret files"
echo "- Prefer managed secret stores in production"

echo ""
echo "Checklist reference: docs/SECURITY_BACKUP_RESTORE_CHECKLIST.md"
