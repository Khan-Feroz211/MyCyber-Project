# 🛡️ MyCyber DLP

<div align="center">

[![Python](https://img.shields.io/badge/Python-3.11-3776AB?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black)](https://react.dev)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791?logo=postgresql&logoColor=white)](https://postgresql.org)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://docs.docker.com/compose)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-CSS-38BDF8?logo=tailwindcss&logoColor=white)](https://tailwindcss.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/Khan-Feroz211/MyCyber-Project/actions/workflows/ci.yml/badge.svg)](https://github.com/Khan-Feroz211/MyCyber-Project/actions)

### AI-Powered Data Leakage Prevention Platform

**Detect PII · Scan Files & Network Traffic · Real-Time Alerts · Security Dashboard**

*Built with FastAPI + React + HuggingFace Transformers — fully containerised, one command to run.*

</div>

---

## ✨ What is MyCyber DLP?

**MyCyber DLP** is a full-stack cybersecurity web application that automatically detects sensitive data leakage across text, files, and network payloads. It uses an AI Named Entity Recognition (NER) model to identify PII (names, emails, phone numbers, credit card numbers, etc.) and flags them with a risk score and recommended action — all visible in a sleek real-time dashboard.

> Built entirely from scratch as a personal project to demonstrate full-stack security engineering, ML integration, and production-grade DevOps practices.

---

## 🎯 Key Features

| Feature | Details |
|---|---|
| 🤖 **AI PII Detection** | HuggingFace `dslim/bert-base-NER` transformer — finds names, orgs, locations, and more |
| 📄 **Multi-mode Scanning** | Scan raw text, base64-encoded files, or network payloads via REST API |
| ⚠️ **Smart Alerts** | Severity levels (CRITICAL / HIGH / MEDIUM / LOW / SAFE) with risk score 0–100 |
| 📊 **Live Dashboard** | Stats cards, pie chart breakdown, recent alerts, full scan history |
| 🔐 **JWT Auth** | Secure register/login with bcrypt + python-jose — every endpoint is protected |
| 🗃️ **Async Database** | SQLAlchemy 2 async + asyncpg + PostgreSQL 16 with Alembic migrations |
| 📈 **Observability** | Prometheus metrics + Grafana dashboards + MLflow experiment tracking |
| 🐳 **One-Command Deploy** | Full Docker Compose stack — development and production configs included |

---

## 🖥️ Application Pages

| Page | Description |
|---|---|
| **Dashboard** | Overview of total scans, critical threats, scan distribution chart, recent alerts |
| **New Scan** | Submit text, file, or network payload — get instant risk score + entity list |
| **Alerts** | All unacknowledged alerts with severity badge and one-click acknowledgement |
| **History** | Paginated log of every scan with severity, risk bar, action, and entity count |
| **Settings** | User profile and account management |

---

## 🚀 Quick Start — Run with Docker

> **Requirements:** [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running.

### 1 — Clone the repo

```bash
git clone https://github.com/Khan-Feroz211/MyCyber-Project.git
cd MyCyber-Project
```

### 2 — Configure your environment

```bash
cp .env.docker.example .env.docker
```

Open `.env.docker` and set these required values:

```env
POSTGRES_PASSWORD=your-strong-db-password
JWT_SECRET=your-random-32-char-secret-here-abc123
```

> Generate a secure JWT secret instantly:
> ```bash
> python -c "import secrets; print(secrets.token_hex(32))"
> ```

### 3 — Start all services

```bash
# Using Make (recommended)
make up

# Or directly with Docker Compose
docker-compose up -d
```

> ⏳ **First run takes 3–5 minutes** — the backend downloads the `dslim/bert-base-NER` AI model (~400 MB). Subsequent starts are instant.

### 4 — Open your browser

| Service | URL |
|---|---|
| 🌐 **Website** | **[http://localhost](http://localhost)** |
| 📖 **API Docs (Swagger)** | [http://localhost:8000/docs](http://localhost:8000/docs) |
| 📊 **Grafana** | [http://localhost:3001](http://localhost:3001) (admin/admin) |
| 🔬 **MLflow** | [http://localhost:5001](http://localhost:5001) |
| 📡 **Prometheus** | [http://localhost:9090](http://localhost:9090) |

### 5 — Register and scan

1. Go to **http://localhost/register** and create your account
2. Navigate to **New Scan** and paste some text (try including a fake name, email, or phone number)
3. View your results on the **Dashboard**

### Stop everything

```bash
make down
```

---

## 📡 REST API

All endpoints (except auth and health) require `Authorization: Bearer <token>`.

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/health` | ❌ | Liveness probe |
| `POST` | `/api/v1/auth/register` | ❌ | Create account |
| `POST` | `/api/v1/auth/login` | ❌ | Obtain JWT token |
| `GET` | `/api/v1/auth/me` | ✅ | Current user info |
| `POST` | `/api/v1/scan/text` | ✅ | Scan plain text for PII |
| `POST` | `/api/v1/scan/file` | ✅ | Scan base64-encoded file |
| `POST` | `/api/v1/scan/network` | ✅ | Scan network payload |
| `GET` | `/api/v1/scan/history` | ✅ | Paginated scan history |
| `GET` | `/api/v1/scan/stats/summary` | ✅ | Aggregated stats |
| `GET` | `/api/v1/alerts` | ✅ | List alerts |
| `POST` | `/api/v1/alerts/acknowledge` | ✅ | Acknowledge an alert |

Interactive docs with live try-it-out at **http://localhost:8000/docs**

---

## 🧰 Tech Stack

| Layer | Technology |
|---|---|
| **Backend** | FastAPI 0.115, SQLAlchemy 2 async, Alembic, asyncpg |
| **Auth** | bcrypt password hashing + python-jose JWT (HS256) |
| **AI / ML** | HuggingFace Transformers — `dslim/bert-base-NER` |
| **Database** | PostgreSQL 16 |
| **Frontend** | React 18, Vite, Tailwind CSS, Recharts, React Router v6 |
| **Serving** | nginx (SPA + API reverse proxy with gzip) |
| **Monitoring** | Prometheus + Grafana + MLflow |
| **Infra** | Docker, Docker Compose, multi-stage builds |
| **CI** | GitHub Actions — flake8 lint + pytest on Python 3.8/3.9/3.10 |

---

## ⚙️ Make Commands

| Command | Description |
|---|---|
| `make up` | Start all services (detached) |
| `make down` | Stop all services |
| `make build` | Rebuild all Docker images (no cache) |
| `make logs` | Follow logs for all services |
| `make logs-backend` | Follow backend logs only |
| `make migrate` | Run Alembic DB migrations inside backend container |
| `make shell-backend` | Open bash shell inside backend container |
| `make shell-db` | Open `psql` inside postgres container |
| `make reset` | Full reset: stop, delete volumes, rebuild from scratch |
| `make prod-up` | Start production stack (4 uvicorn workers, no live-reload) |
| `make monitoring-up` | Start only MLflow + Prometheus + Grafana |

---

## 🔧 Environment Variables

Copy `.env.docker.example` → `.env.docker`. **Never commit `.env.docker`.**

| Variable | Description | Default / Example |
|---|---|---|
| `POSTGRES_USER` | PostgreSQL username | `postgres` |
| `POSTGRES_PASSWORD` | PostgreSQL password *(required)* | `s3cur3pass!` |
| `POSTGRES_DB` | Database name | `mycyber_dlp` |
| `JWT_SECRET` | HMAC signing secret ≥ 32 chars *(required)* | `openssl rand -hex 32` |
| `JWT_EXPIRE_HOURS` | Token lifetime in hours | `24` |
| `APP_ENV` | `development` or `production` | `development` |
| `LOG_LEVEL` | Python log level | `INFO` |
| `CORS_ORIGINS` | Comma-separated allowed origins | `http://localhost` |
| `NER_MODEL_NAME` | HuggingFace model identifier | `dslim/bert-base-NER` |
| `NER_MIN_CONFIDENCE` | Minimum NER confidence threshold | `0.85` |
| `USE_TRANSFORMER` | Enable HuggingFace NER | `true` |
| `GRAFANA_USER` | Grafana admin username | `admin` |
| `GRAFANA_PASSWORD` | Grafana admin password | `admin` |

---

## 🏗️ Project Structure

```
MyCyber-Project/
├── backend/
│   ├── app/
│   │   ├── main.py           # FastAPI application + middleware
│   │   ├── config.py         # Pydantic settings (reads .env.docker)
│   │   ├── db/               # SQLAlchemy models & async session
│   │   ├── routers/          # auth · scan · alerts · health · metrics
│   │   ├── services/         # PII scanner, alert logic, auth service
│   │   └── models/           # Pydantic request/response schemas
│   ├── alembic/              # Database migration scripts
│   ├── tests/                # pytest-asyncio test suite
│   ├── requirements.txt
│   └── Dockerfile            # Multi-stage Python build
├── frontend/
│   ├── src/
│   │   ├── api/              # Axios API clients (scans, alerts, auth)
│   │   ├── components/       # Reusable UI (StatCard, SeverityBadge…)
│   │   ├── context/          # AuthContext (JWT + user state)
│   │   └── pages/            # Dashboard · Scan · Alerts · History · Settings
│   ├── nginx.conf            # nginx SPA + /api proxy config
│   └── Dockerfile            # Multi-stage Node build → nginx runtime
├── monitoring/
│   ├── prometheus.yml        # Prometheus scrape config
│   └── grafana/              # Grafana dashboards & provisioning
├── docker-compose.yml        # Development stack (live-reload)
├── docker-compose.prod.yml   # Production stack (4 workers, no mounts)
├── .env.docker.example       # Environment template
├── Makefile                  # Convenience commands
└── .github/workflows/ci.yml  # GitHub Actions CI pipeline
```

---

## 🗺️ Roadmap

| Status | Milestone |
|---|---|
| ✅ | Core platform: FastAPI + React dashboard, PII detection, real-time alerts |
| ✅ | JWT authentication, PostgreSQL, Alembic migrations |
| ✅ | Docker Compose (dev + prod), multi-stage builds |
| ✅ | MLflow experiment tracking + Prometheus + Grafana observability |
| ✅ | GitHub Actions CI/CD pipeline (flake8 + pytest) |
| 🔜 | Stripe SaaS billing tiers (Free / Pro / Enterprise) |
| 🔜 | Kubernetes deployment manifests + Helm chart |
| 🔜 | Production launch + custom domain + SSL (Let's Encrypt) |

---

## 🤝 Contributing

Pull requests are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 📄 License

MIT — see [LICENSE](LICENSE).

---

<div align="center">
  Built with ❤️ by <a href="https://github.com/Khan-Feroz211">Khan-Feroz211</a>
</div>
