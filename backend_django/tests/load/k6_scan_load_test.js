/**
 * MyCyber DLP — k6 load test for the Django scan engine.
 *
 * Targets the authenticated POST /api/v1/scan/text endpoint.
 * A short setup() runs once to obtain a JWT (register + login), then VUs
 * replay scan requests.
 *
 * Usage (run the Django dev server first, e.g. on port 8123)::
 *
 *   set DATABASE_URL=sqlite:///./bench.db
 *   manage.py runserver 127.0.0.1:8123 --noreload --threaded
 *
 *   k6 run tests/load/k6_scan_load_test.js
 *
 * Scenarios exercised:
 *   - scan_text_safe   : a clean prompt (SAFE, no alert audit write).
 *   - scan_text_risky  : a prompt with a credit-card number (CRITICAL/HIGH →
 *     triggers Alert + extra EVENT_ALERT_CREATED audit write).
 */
import http from "k6/http";
import { check, group, sleep } from "k6";
import { Counter, Trend } from "k6/metrics";

const scanDuration = new Trend("scan_duration");
const errors = new Counter("scan_errors");

const BASE_URL = __ENV.BASE_URL || "http://127.0.0.1:8123";
const USER_EMAIL = __ENV.USER_EMAIL || `load-${__VU}-${__ITER}@test.com`;

export const options = {
  scenarios: {
    rampup: {
      executor: "ramping-vus",
      startVUs: 1,
      stages: [
        { duration: "30s", target: 10 }, // warm-up to 10 VUs
        { duration: "1m", target: 25 },   // peak to 25 VUs
        { duration: "1m", target: 0 },    // ramp-down
      ],
      gracefulRampDown: "15s",
    },
  },
  thresholds: {
    "http_req_duration": ["p(95)<500"],
    "http_req_failed": ["rate<0.05"],
    "scan_errors": ["count<10"],
  },
};

const SAFE_TEXT = "Quarterly report: marketing spend, headcount, and roadmap updates.";
const RISKY_TEXT = "Card on file: 4111111111111111 expires 12/27. Do not share.";

export function setup() {
  // Register a fresh account + log in to obtain a Bearer JWT.
  http.post(`${BASE_URL}/api/v1/auth/register`, JSON.stringify({
    email: USER_EMAIL, password: "password123", full_name: "Load Test",
  }), { headers: { "Content-Type": "application/json" } });

  const login = http.post(`${BASE_URL}/api/v1/auth/login`, `username=${USER_EMAIL}&password=password123`, {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
  });
  check(login, { "login 200": (r) => r.status === 200 });
  const token = JSON.parse(login.body).access_token;
  return { token: `Bearer ${token}` };
}

export default function (data) {
  const params = { headers: { "Content-Type": "application/json", Authorization: data.token } };

  group("scan_text_safe", function () {
    const res = http.post(`${BASE_URL}/api/v1/scan/text`, JSON.stringify({ text: SAFE_TEXT }), params);
    const ok = check(res, {
      "safe scan 200": (r) => r.status === 200,
      "safe severity": (r) => JSON.parse(r.body).severity === "SAFE",
    });
    if (!ok) errors.add(1);
    scanDuration.add(res.timings.duration);
  });

  sleep(0.05);

  group("scan_text_risky", function () {
    const res = http.post(`${BASE_URL}/api/v1/scan/text`, JSON.stringify({ text: RISKY_TEXT }), params);
    const ok = check(res, {
      "risky scan 200": (r) => r.status === 200,
      "risky severity": (r) => ["CRITICAL", "HIGH"].includes(JSON.parse(r.body).severity),
    });
    if (!ok) errors.add(1);
    scanDuration.add(res.timings.duration);
  });

  sleep(0.05);
}
