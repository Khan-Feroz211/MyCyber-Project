# MyCyber — Open-Source DLP Platform

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-8b5cf6?style=for-the-badge" />
  <img src="https://img.shields.io/badge/python-3.11-a78bfa?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/React-18-7c3aed?style=for-the-badge&logo=react&logoColor=white" />
  <img src="https://img.shields.io/badge/FastAPI-0.115-6d28d9?style=for-the-badge&logo=fastapi&logoColor=white" />
  <img src="https://img.shields.io/badge/Docker-ready-8b5cf6?style=for-the-badge&logo=docker&logoColor=white" />
  <img src="https://img.shields.io/badge/Made%20in-Pakistan-005534?style=for-the-badge" />
</p>

<p align="center">
  <strong>Enterprise-grade Data Loss Prevention with real-time threat scanning, LLM-aware content filtering, and zero-trust access control.</strong>
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> ·
  <a href="#-features">Features</a> ·
  <a href="#-architecture">Architecture</a> ·
  <a href="#-contributing">Contributing</a> ·
  <a href="#-license">License</a>
</p>

---

## What is MyCyber?

MyCyber is a self-hostable, open-source Data Loss Prevention platform built for organisations that cannot afford to lose sensitive data. It scans files, text, API calls, and LLM prompts in real time — detecting PII, credentials, financial data, and prompt injection attempts before they leave your perimeter.

```
User uploads file / sends LLM prompt
         ↓
  Pre-scan (prompt injection check)
         ↓
  40+ DLP rule engine (regex + ML)
         ↓
  PII · Credentials · Financial · Malware
         ↓
  Score → Alert → Notify Admin
         ↓
  Post-scan LLM response check
```

## ✨ Features

| Category | Capability |
|---|---|
| **Scanning** | 40+ DLP rule categories — CNIC, IBAN, API keys, passwords, PII |
| **LLM DLP** | Pre/post-scan pipeline with auto-redaction and auto-deactivation |
| **Auth** | JWT + refresh tokens, TOTP MFA, RBAC (user / admin) |
| **Alerts** | Real-time WebSocket push + email notifications |
| **Scheduling** | Cron-based scheduled scans with management UI |
| **Admin** | Incident panel with CSV / HTML / JSON export |
| **Monitoring** | Prometheus metrics + Grafana dashboards |
| **Deployment** | Docker Compose — up in under 10 minutes |

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- Node.js 20+ (for local frontend dev)
- Python 3.11+ (for local backend dev)

### 1. Clone
```bash
git clone https://github.com/Khan-Feroz211/MyCyber-Project.git
cd MyCyber-Project
```

### 2. Configure environment
```bash
cp .env.example .env.docker
# Edit .env.docker — set ANTHROPIC_API_KEY, JWT_SECRET_KEY, SMTP config
```

### 3. Start
```bash
docker-compose up -d
```

### 4. Open
| Service | URL |
|---|---|
| Frontend | http://localhost:80 |
| Backend API | http://localhost:8000 |
| API Docs | http://localhost:8000/docs |
| Grafana | http://localhost:3001 |
| MLflow | http://localhost:5001 |

> Default admin credentials are set via `FIRST_ADMIN_EMAIL` / `FIRST_ADMIN_PASSWORD` in your `.env.docker`.

### Local Frontend Development

Run these commands from the project root:

```bash
npm run install:frontend
npm run dev
```

The root `npm run dev` command forwards to the Vite app inside `frontend`.

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────┐
│                   React SPA (Vite)                   │
│          Tailwind · framer-motion · Recharts         │
└─────────────────┬───────────────────────────────────┘
                  │ HTTPS / WebSocket
┌─────────────────▼───────────────────────────────────┐
│              FastAPI (Python 3.11)                   │
│   JWT Auth · RBAC · Rate limiting · Audit log        │
├──────────────┬──────────────┬────────────────────────┤
│  DLP Engine  │  LLM Pipeline│  Celery Workers        │
│  40+ rules   │  Claude API  │  Scheduled scans       │
└──────┬───────┴──────────────┴────────┬───────────────┘
       │                               │
┌──────▼───────┐              ┌────────▼───────────────┐
│  PostgreSQL  │              │   Redis (broker/cache) │
└──────────────┘              └────────────────────────┘
```

## 🔑 API Keys Needed

| API | Free Tier | Purpose |
|---|---|---|
| Anthropic Claude | None (usage-based) | LLM DLP pipeline |
| VirusTotal | 500 req/day | Malware scanning |
| HIBP | Free | Password breach check |
| SMTP | Free (Gmail/SG) | Alert emails |

## 🤝 Contributing

We welcome contributions of all kinds — bug fixes, new DLP rules, UI improvements, docs, or translations.

1. Fork the repo
2. Create a branch: `git checkout -b feat/your-feature`
3. Make your changes and add tests
4. Run checks: `pytest` and `npm run build`
5. Open a pull request using the [PR template](.github/pull_request_template.md)

Please read [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before contributing.

### Good first issues
Look for issues tagged [`good first issue`](https://github.com/Khan-Feroz211/MyCyber-Project/issues?q=label%3A%22good+first+issue%22) — these are scoped and beginner-friendly.

## 🛡 Security

Found a vulnerability? **Please do not open a public issue.** Email **f24605023@nutech.edu.pk** directly. We aim to respond within 48 hours.

See [SECURITY.md](SECURITY.md) for our full disclosure policy.

## ✅ Security & Compliance

- Encryption at rest for sensitive fields with key-versioned KMS flow
- Immutable hash-chained audit logging for security events
- RBAC enforcement for admin/security operations
- Helm/Kubernetes deployment assets under `helm/` and `k8s/`
- Security architecture reference: `SECURITY_ARCHITECTURE.md`
- Compliance scaffolding:
  - `docs/compliance/SOC2_CONTROL_MAPPING.md`
  - `docs/compliance/ISO27001_ANNEX_A_CHECKLIST.md`
  - `tests/load/README.md` for k6 throughput documentation

## 📄 License

MIT — see [LICENSE](LICENSE) for details.

Copyright © 2026 Feroz U Din — MyCyber Project Contributors.

---

<p align="center">Built with ❤️ at NUTECH, Pakistan</p>
