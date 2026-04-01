# 🛡️ MyCyber DLP

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688.svg)
![React](https://img.shields.io/badge/React-18-61DAFB.svg)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791.svg)
![Docker](https://img.shields.io/badge/Docker-ready-2496ED.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

**AI-powered Data Leakage Prevention platform.**  
PII detection · File scanning · Network analysis · Real-time alerts · Security dashboard.

</div>

---

## 🧰 Tech Stack

| Layer | Technology |
|---|---|
| **Backend** | FastAPI 0.115, SQLAlchemy 2 async, Alembic, asyncpg |
| **Auth** | bcrypt + python-jose JWT (HS256) |
| **ML / NER** | HuggingFace Transformers — `dslim/bert-base-NER` |
| **Database** | PostgreSQL 16 |
| **Frontend** | React 18, Vite, Tailwind CSS, Recharts, React Router v6 |
| **Serving** | nginx (static SPA + API reverse proxy) |
| **Infra** | Docker, Docker Compose, multi-stage builds |

---

## 🚀 Quick Start with Docker

### Step 1 — Configure environment

```bash
cp .env.docker.example .env.docker
# Open .env.docker and fill in real values:
#   POSTGRES_PASSWORD, JWT_SECRET (min 32 chars), etc.
```

### Step 2 — Start all services

```bash
make up
# or: docker-compose up -d
```

### Step 3 — Open the dashboard

```
http://localhost
```

### Step 4 — Register and scan

Create an account at `/register`, then navigate to **New Scan** to run your first PII detection.

---

## 📡 API Endpoints

All scan and alert endpoints require a `Bearer <token>` header obtained from `/api/v1/auth/login`.

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/health` | ❌ | Liveness probe |
| `POST` | `/api/v1/auth/register` | ❌ | Create account |
| `POST` | `/api/v1/auth/login` | ❌ | Obtain JWT token |
| `GET` | `/api/v1/auth/me` | ✅ | Current user info |
| `POST` | `/api/v1/scan/text` | ✅ | Scan plain text |
| `POST` | `/api/v1/scan/file` | ✅ | Scan base64-encoded file |
| `POST` | `/api/v1/scan/network` | ✅ | Scan network payload |
| `GET` | `/api/v1/scan/history` | ✅ | Paginated scan history |
| `GET` | `/api/v1/scan/stats/summary` | ✅ | Aggregated stats |
| `GET` | `/api/v1/alerts` | ✅ | List alerts |
| `POST` | `/api/v1/alerts/acknowledge` | ✅ | Acknowledge an alert |

Interactive docs available at `http://localhost:8000/docs` (dev mode).

---

## ⚙️ Make Commands

| Command | Description |
|---|---|
| `make up` | Start all services in detached mode |
| `make down` | Stop all services |
| `make build` | Rebuild all Docker images (no cache) |
| `make logs` | Follow logs for all services |
| `make logs-backend` | Follow backend logs only |
| `make migrate` | Run Alembic DB migrations inside backend container |
| `make shell-backend` | Open bash shell inside backend container |
| `make shell-db` | Open `psql` inside postgres container |
| `make reset` | Full reset: stop, delete volumes, rebuild |
| `make prod-up` | Start production stack |
| `make prod-down` | Stop production stack |

---

## 🔧 Environment Variables

Copy `.env.docker.example` → `.env.docker` and fill in values. **Never commit `.env.docker`.**

| Variable | Description | Example |
|---|---|---|
| `POSTGRES_USER` | PostgreSQL username | `postgres` |
| `POSTGRES_PASSWORD` | PostgreSQL password | `s3cur3pass!` |
| `POSTGRES_DB` | Database name | `mycyber_dlp` |
| `JWT_SECRET` | HMAC signing secret (≥ 32 chars) | `openssl rand -hex 32` |
| `JWT_EXPIRE_HOURS` | Token lifetime in hours | `24` |
| `APP_ENV` | `development` or `production` | `development` |
| `LOG_LEVEL` | Python log level | `INFO` |
| `CORS_ORIGINS` | Comma-separated allowed origins | `http://localhost` |
| `NER_MODEL_NAME` | HuggingFace model identifier | `dslim/bert-base-NER` |
| `NER_MIN_CONFIDENCE` | Minimum NER entity confidence | `0.85` |
| `USE_TRANSFORMER` | Enable HuggingFace NER | `true` |

---

## 🗺️ Roadmap

| Day | Milestone |
|---|---|
| ✅ 1–4 | Core platform: FastAPI + React dashboard, PII detection, alerts |
| 🔜 5 | MLflow experiment tracking + Prometheus + Grafana observability |
| 🔜 6 | GitHub Actions CI/CD pipeline + Bandit security scanning |
| 🔜 7 | Stripe SaaS billing tiers (Free / Pro / Enterprise) |
| 🔜 8 | Kubernetes deployment manifests + Helm chart |
| 🔜 9 | Production launch + custom domain + SSL (Let's Encrypt) |

---

## 🏗️ Project Structure

```
MyCyber-Project/
├── backend/
│   ├── app/
│   │   ├── main.py          # FastAPI application entry point
│   │   ├── config.py        # Pydantic settings
│   │   ├── db/              # SQLAlchemy models & session
│   │   ├── routers/         # API route handlers
│   │   ├── services/        # Business logic & NER scanner
│   │   └── models/          # Pydantic schemas
│   ├── alembic/             # DB migration scripts
│   ├── tests/               # pytest test suite
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── api/             # Axios API clients
│   │   ├── components/      # Reusable UI components
│   │   ├── context/         # AuthContext
│   │   └── pages/           # Route-level pages
│   ├── nginx.conf           # nginx SPA + proxy config
│   └── Dockerfile
├── docker-compose.yml       # Development stack
├── docker-compose.prod.yml  # Production stack
├── .env.docker.example      # Environment template
└── Makefile                 # Convenience commands
```

---

## 📄 License

MIT — see [LICENSE](LICENSE).
