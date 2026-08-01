# Load Testing: `/api/v1/scan/text`

This document records the latest k6 run for scan throughput.

## Command

```bash
docker run --rm --network host -i \
  -e BASE_URL=http://localhost:8000 \
  -e JWT_TOKEN=<access_token> \
  -e VUS=5 \
  -e DURATION=10s \
  -v /mnt/d/Mycyber/MyCyber-Project:/work \
  grafana/k6 run --summary-export=/work/reports/k6-summary.json /work/scripts/load_test_scans.js
```

## Latest Measurement (2026-08-01)

- Requests: **699**
- Throughput: **23.37 req/s** (`http_reqs.rate`)
- Median latency: **29.15 ms**
- P95 latency: **115.63 ms**
- Success ratio: **17.74%** (`scan_success_rate`)

Source: `reports/k6-summary.json`.

