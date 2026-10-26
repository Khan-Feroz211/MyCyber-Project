"""Minimal measured RPS benchmark for the Django scan endpoint.

Uses only the Python standard library (no k6/httpx required) so it runs in
any environment with the venv interpreter.  Start the dev server first::

    set DATABASE_URL=sqlite:///./bench.db
    manage.py runserver 127.0.0.1:8123 --noreload --settings=mycyber.settings.bench

    python tests/load/bench_scan.py http://127.0.0.1:8123

Reports mean / p95 latency and requests-per-second for the authenticated
POST /api/v1/scan/text endpoint (the product's hot path), plus a read-only
baseline GET /api/v1/billing/plans.
"""
from __future__ import annotations

import json
import statistics
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlencode

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8123"
CONCURRENCY = int(sys.argv[2]) if len(sys.argv) > 2 else 16
REQUESTS = int(sys.argv[3]) if len(sys.argv) > 3 else 320


def _post(url, body, headers):
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={**headers, "Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        resp.read()
        return resp.status


def _get(url, headers):
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=60) as resp:
        resp.read()
        return resp.status


def auth_token():
    user = f"bench-{int(time.time())}@test.com"
    try:
        _post(f"{BASE_URL}/api/v1/auth/register", {"email": user, "password": "password123", "full_name": "Bench"}, {})
    except urllib.error.HTTPError:
        pass  # already registered
    req = urllib.request.Request(f"{BASE_URL}/api/v1/auth/login", data=urlencode({"username": user, "password": "password123"}).encode(), method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urllib.request.urlopen(req, timeout=60) as resp:
        body = json.loads(resp.read().decode())
    print(f"Authenticated as {user}")
    return {"Authorization": f"Bearer {body['access_token']}"}


def measure(label, fn, args, concurrency=CONCURRENCY, n=REQUESTS):
    latencies = []
    errors = []

    def worker():
        t0 = time.perf_counter()
        try:
            fn(*args)
            latencies.append(time.perf_counter() - t0)
        except urllib.error.HTTPError as e:
            try:
                detail = e.read()[:120]
            except Exception:  # noqa: BLE001
                detail = b""
            errors.append(f"HTTP {e.code}: {detail}")
        except Exception as e:  # noqa: BLE001
            errors.append(f"{type(e).__name__}: {e}")

    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futs = [ex.submit(worker) for _ in range(n)]
        for _ in as_completed(futs):
            pass
    elapsed = time.perf_counter() - start
    rps = n / elapsed if elapsed else 0
    mean_ms = statistics.mean(latencies) * 1000 if latencies else 0
    if latencies:
        idx = int(len(latencies) * 0.95)
        p95 = max(latencies) * 1000 if idx >= len(latencies) else (sorted(latencies)[idx] * 1000)
    else:
        p95 = 0
    sample = errors[0] if errors else ""
    print(f"{label}: rps={rps:6.1f}  mean={mean_ms:6.1f}ms  p95={p95:6.1f}ms  errors={len(errors)}/{n}  sample={sample}")


def main():
    token = auth_token()

    def scan_text(headers, body):
        return _post(f"{BASE_URL}/api/v1/scan/text", body, headers)

    measure("POST /scan/text (safe)   ", scan_text, (token, {"text": "Quarterly roadmap and headcount briefing."}))
    measure("POST /scan/text (risky)  ", scan_text, (token, {"text": "Card: 4111111111111111 expires 12/27"}))
    measure("GET  /billing/plans (baseline)", _get, (f"{BASE_URL}/api/v1/billing/plans", token))


if __name__ == "__main__":
    main()
