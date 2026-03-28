# MyCyber DLP Platform

A production-ready, **microservices-based Data Loss Prevention (DLP)** platform built with FastAPI, Redis, PostgreSQL, scikit-learn, and MLflow — packaged for Docker Compose and Kubernetes.

## Architecture

```
Endpoints → [Ingestion Service] → Redis Queue
                                       ↓
                          [ML Inference Service]
                                       ↓
                           [Policy Engine Service] → [Alert Service] → Slack/Email
                                       ↓
                           [Dashboard API] ← Browser / API clients
```

All services expose:
- `/healthz` — health check
- `/metrics` — Prometheus metrics
- OpenTelemetry traces → OTLP collector → Jaeger

## Services

| Service | Port | Responsibility |
|---------|------|----------------|
| `ingestion` | 8000 | Receive file events, normalise, push to Redis |
| `ml-inference` | 8001 | PII classification (heuristic + sklearn RF) |
| `policy-engine` | 8002 | Apply DLP rules, emit ALLOW/WARN/BLOCK |
| `alert` | 8003 | Dispatch Slack / webhook alerts |
| `dashboard-api` | 8080 | JWT/RBAC REST API + WebSocket live feed |

## ML Pipeline

DVC-managed pipeline: `preprocess → train → evaluate → register`

- Tracked with **MLflow 3.9.0** (patched against deserialization CVEs)
- Drift monitoring via **Evidently AI**
- Automated retraining trigger on drift > threshold

## Quick Start

```bash
cp .env.example .env
# Edit .env — set POSTGRES_PASSWORD, JWT_SECRET, MINIO_ROOT_PASSWORD
docker-compose up --build
```

Open:
- Dashboard API docs: http://localhost:8080/docs
- MLflow UI: http://localhost:5000
- Grafana: http://localhost:3000 (admin / from .env)
- Prometheus: http://localhost:9090

## Dependency Security

All dependencies have been pinned to patched versions:

| Package | Version | Vulnerabilities Fixed |
|---------|---------|----------------------|
| `python-jose` | 3.4.0 | Algorithm confusion with OpenSSH ECDSA keys |
| `python-multipart` | 0.0.22 | Arbitrary file write + DoS via malformed boundary |
| `torch` | 2.6.0 | `torch.load` RCE with `weights_only=True` |
| `mlflow` | 3.9.0 | Remote code execution via deserialization |
| `transformers` | 4.48.0 | Arbitrary code execution |

## CI/CD

GitHub Actions pipeline: **lint → test → security scan → Docker build → staging → production (manual)**

See [`.github/workflows/deploy.yml`](.github/workflows/deploy.yml)

## 6-Month Roadmap

See [`docs/roadmap.md`](docs/roadmap.md)

## Directory Structure

```
├── services/
│   ├── ingestion/       FastAPI ingestion service
│   ├── ml-inference/    ML classification service
│   ├── policy-engine/   DLP rule evaluation service
│   ├── alert/           Alert dispatch service
│   └── dashboard-api/   REST API + WebSocket dashboard
├── ml-pipeline/         DVC + MLflow + Evidently pipeline
├── infra/
│   ├── docker/          Prometheus, Grafana, OTel configs
│   └── k8s/             Kubernetes manifests
├── .github/workflows/   CI/CD pipeline
├── tests/               Pytest unit tests
├── docs/                Roadmap and architecture docs
└── docker-compose.yml   Local development stack
```
