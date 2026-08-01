# TODO — Tomorrow's Work

## Remaining Tasks

### 1. Run Tests (BLOCKER)
- **Problem:** Test suite hangs during collection (timeout after ~25s)
- **Check:** `cd backend && .venv-fresh/bin/python -m pytest tests/ -x -q --tb=short -p no:cacheprovider`
- **Likely cause:** `load_ner_model()` in `main.py` lifespan, or `mlflow` import in `tracker.py`
- **Fix attempt:** mlflow import already made optional in `tracker.py`. Try:
  ```bash
  timeout 30 .venv-fresh/bin/python -m pytest tests/test_kms_encryption.py -x -v
  ```
- **Goal:** Get all existing tests passing + new tests for KMS, audit log, RBAC

### 2. Phase 4 — k6 Load Test (complete)
- Create `tests/load/README.md` with measured RPS (run `k6 run scripts/load_test_scans.js` against a running instance)
- Document throughput number in README

### 3. Phase 5 — SECURITY_ARCHITECTURE.md
- Create at project root documenting:
  - Data storage (Postgres tables, Redis, file/quarantine storage)
  - Processing (NER, LLM pipeline)
  - Egress (Claude/OpenAI API calls via LLM_BASE_URL, DEPLOYMENT_REGION=PK sovereign mode)
  - What stays vs. leaves the deployment perimeter

### 4. Phase 6 — Compliance Scaffolding
- Create `docs/compliance/SOC2_CONTROL_MAPPING.md`
- Create `docs/compliance/ISO27001_ANNEX_A_CHECKLIST.md`
- Mark satisfied controls vs. policy-needed controls

### 5. Phase 7 — README Update
- Add "Security & Compliance" section to `README.md`
- Summarize: encryption at rest, immutable audit logging, RBAC, Helm/K8s, security docs, compliance

## Files to Review
- `backend/app/mlops/tracker.py` — mlflow optional import (done, verify)
- `backend/app/dependencies.py` — request param removed, Optional import added
- `backend/app/routers/admin_security.py` — `_require_admin` now checks `role == "admin"`
- `backend/app/routers/auth.py` — removed broken `ensure_user_subscription` import; audit logging added
- `backend/app/routers/scheduled_scan.py` — added `response_model=None` to 204 route

## Commands to Run Tomorrow
```bash
# Test baseline
cd backend && timeout 30 .venv-fresh/bin/python -m pytest tests/test_kms_encryption.py -x -v

# If tests pass, run full suite
cd backend && timeout 120 .venv-fresh/bin/python -m pytest tests/ -v --tb=short

# If tests still hang, investigate lifespan
cd backend && timeout 15 /mnt/d/Mycyber/MyCyber-Project/.venv-fresh/bin/python -c "
import os
os.environ['JWT_SECRET_KEY']='test-key-32-chars-long-for-testing!'
os.environ['DATABASE_URL']='sqlite+aiosqlite:///./test.db'
os.environ['ENCRYPTION_MASTER_KEY']='test-encryption-key-32-bytes-long!!!'
import asyncio
from app.main import app
async def t():
    from contextlib import asynccontextmanager
    async def tl(app):
        yield
    print('App OK, routes:', len(app.routes))
asyncio.run(t())
"
```
