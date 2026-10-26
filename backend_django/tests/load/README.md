# Load Testing — MyCyber DLP (Django backend)

This directory contains load-test artefacts for the `backend_django/` stack.

## TL;DR — measured results

Measured against the **Django development server** (`runserver`, threaded) backed by
an **SQLite file database** (bench profile, MFA-only JWT auth), on `127.0.0.1:8123`:

| Scenario (concurrency × requests)      | Endpoint                       | RPS   | mean   | p95     | errors |
| -------------------------------------- | ------------------------------ | ----- | ------ | ------- | ------ |
| 4 × 120                                | `POST /scan/text` (safe)       | 10.8  | 366 ms | 907 ms  | 0/120  |
| 4 × 120                                | `POST /scan/text` (risky)      | 6.9   | 577 ms | 1818 ms | 0/120  |
| 4 × 120                                | `GET /billing/plans` (read)    | 68.6  | 58 ms  | 113 ms  | 0/120  |
| 16 × 320                               | `POST /scan/text` (safe)       | 10.8  | 1451ms | 6188 ms | 0/320  |
| 16 × 320                               | `GET /billing/plans` (read)    | 69.0  | 224 ms | 708 ms  | 0/320  |

**Reading the numbers.** The scan hot path writes **3 rows per request**
(`ScanRecord` + an `EVENT_SCAN` audit entry + an `Alert` when the severity is
HIGH/CRITICAL). Under SQLite those writes serialise on a single-file lock, so
throughput is write-bound at ~7–11 RPS and degrades under high concurrency
(latency climbs to the SQLite lock timeout). The read-only baseline stays flat
at ~69 RPS, confirming the **scanner engine itself is not the bottleneck** — the
regex engine completes in tens of milliseconds; the ceiling here is the
single-process dev server + SQLite writer lock.

> **Production extrapolation.** A real deployment (Gunicorn/uvicorn workers +
> PostgreSQL + Redis) removes both limits: the dev server becomes a multi-worker
> process pool and PostgreSQL MVCC handles concurrent writes without a global
> write lock. Expect the scan path to scale with the number of workers and the
> Postgres connection pool size.

## Running the benchmark

### Prerequisites

- A running Django server. The benchmark authenticates itself, so start it with
  a **file** SQLite database (the test settings use `:memory:`, which is
  per-connection and won't persist across the migrate/server processes):

  ```bat
  set DJANGO_SECRET_KEY=django-dev-secret-key-32ch!
  set JWT_SECRET_KEY=jwt-test-secret-key-32bytes!!
  set ENCRYPTION_MASTER_KEY=test-encryption-key-32-bytes-long!!!
  set SAFEPAY_SECRET_KEY=test-safepay-secret-key-32-chars-long!!
  set DATABASE_URL=sqlite:///./bench.db
  manage.py migrate --settings=mycyber.settings.bench --no-input
  manage.py runserver 127.0.0.1:8123 --noreload --settings=mycyber.settings.bench
  ```

  The `mycyber.settings.bench` profile is identical to dev but uses the MFA-only
  `MFATokenAuthentication` (PyJWT HS256) so tokens issued by the auth service are
  accepted by the live server.

### Stdlib benchmark (no extra deps)

```bat
.venv-django\Scripts\python.exe tests/load/bench_scan.py http://127.0.0.1:8123 <concurrency> <requests>
```

`bench_scan.py` registers a user, logs in for a JWT, then fires concurrent
authenticated `POST /scan/text` requests (one safe, one card-number payload)
plus a read-only `GET /billing/plans` baseline. It prints RPS, mean latency,
p95 latency, and error counts.

### k6

[k6](https://k6.io) is not installed in this environment, so the numbers above
were produced with the stdlib benchmark. The k6 script is provided for CI/
production use:

```bash
k6 run tests/load/k6_scan_load_test.js
```

The script ramps to 10 → 25 VUs and exercises both the `scan_text_safe` and
`scan_text_risky` groups, asserting `<5%` failures and p95 latency `<500ms`
(against Postgres-backed deployments; against the SQLite dev server the
SQLite lock timeout will exceed this, as documented above).

## What is being measured

- **Auth overhead**: every request is a real login (register + `POST /login`
  form-encoded → JWT) replayed per-VU, so the numbers include PyJWT HS256
  verification + a `User` lookup.
- **Scan engine**: `perform_scan` regex pass over the prompt (NER/transformers
  are lazy and not loaded in the benchmark, so this is the regex-only path).
- **Persistence**: `save_scan` writes a `ScanRecord`, appends an `EVENT_SCAN`
  audit entry (HMAC-SHA256 hash-chained), increments `scan_count_month`, and —
  for the risky payload — creates an `Alert` and an audit entry. These are the
  writes that bind throughput under SQLite.
