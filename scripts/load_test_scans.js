/**
 * MyCyber DLP — k6 Load Test
 *
 * Usage:
 *   # Install k6: https://k6.io/docs/getting-started/installation
 *   k6 run scripts/load_test_scans.js
 *
 *   # With custom VUs / duration:
 *   k6 run -e VUS=50 -e DURATION=300s scripts/load_test_scans.js
 *
 * This script measures the throughput (requests/sec) of the /api/v1/scan/text
 * endpoint.  Run against a production deployment to capture the official
 * load-tested number.
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Counter, Rate } from 'k6/metrics';

const scanLatency = new Trend('scan_latency_ms');
const requestsTotal = new Counter('requests_total');
const scanErrors = new Counter('scan_errors');
const scanSuccessRate = new Rate('scan_success_rate');

const VUS = __ENV.VUS ? parseInt(__ENV.VUS) : 20;
const DURATION = __ENV.DURATION || '120s';
const BASE_URL = __ENV.BASE_URL || 'http://localhost:8000';
const JWT_TOKEN = __ENV.JWT_TOKEN || '';

export const options = {
  stages: [
    { duration: '10s', target: VUS },   // ramp-up
    { duration: DURATION, target: VUS }, // sustain
    { duration: '10s', target: 0 },     // ramp-down
  ],
  thresholds: {
    'http_req_duration{type:scan}': ['p(95)<2000'],       // 95% of scans < 2s
    'scan_success_rate': ['rate>0.95'],                     // >95% success
    'requests_total': ['count>0'],
  },
  tags: { test_type: 'load_test' },
};

const SAFE_TEXT =
  'The quick brown fox jumps over the lazy dog. No sensitive data here.';

function scanText() {
  const url = `${BASE_URL}/api/v1/scan/text`;
  const payload = JSON.stringify({ text: SAFE_TEXT });

  const params = {
    headers: {
      'Content-Type': 'application/json',
      ...(JWT_TOKEN ? { Authorization: `Bearer ${JWT_TOKEN}` } : {}),
    },
    tags: { type: 'scan' },
  };

  const res = http.post(url, payload, params);
  requestsTotal.add(1);

  const ok = check(res, {
    'status is 200': (r) => r.status === 200,
    'has scan_id': (r) => {
      try {
        const body = JSON.parse(r.body);
        return 'scan_id' in body;
      } catch (e) {
        return false;
      }
    },
    'severity is SAFE': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.severity === 'SAFE';
      } catch (e) {
        return false;
      }
    },
  });

  scanSuccessRate.add(ok);
  if (!ok) {
    scanErrors.add(1);
  }

  scanLatency.add(res.timings.duration);
}

export default function () {
  scanText();
  sleep(0.1); // 100ms think time between requests
}
