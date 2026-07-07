# MyCyber DLP — Project & Business Document

**Version**: 1.0 · **Date**: June 2026 · **Classification**: Confidential

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Product Overview](#2-product-overview)
3. [Technical Architecture](#3-technical-architecture)
4. [Market Analysis](#4-market-analysis)
5. [Financial Model](#5-financial-model)
6. [Intellectual Property & Rights Management](#6-intellectual-property--rights-management)
7. [Go-to-Market Strategy](#7-go-to-market-strategy)
8. [Operations Plan](#8-operations-plan)
9. [Risk Management](#9-risk-management)
10. [Roadmap](#10-roadmap)
11. [Team](#11-team)
12. [Funding & Investment Structure](#12-funding--investment-structure)

---

## 1. Executive Summary

**MyCyber** is Pakistan's first enterprise-grade, self-hostable Data Loss Prevention (DLP) platform. Built on a modern open-core architecture, MyCyber scans files, text, API payloads, and Large Language Model (LLM) prompts in real time — detecting and blocking leakage of sensitive data such as CNICs, IBANs, API keys, credentials, and personally identifiable information before it leaves an organisation's perimeter.

### The Opportunity

Pakistan has a rapidly growing digital economy with 5.2M+ registered businesses, a newly enacted Personal Data Protection Act (PDPA 2023), and zero locally built DLP solutions. Global alternatives (Forcepoint, Symantec, Microsoft Purview) cost PKR 1.1M+/year and have no Pakistani data-pattern support. MyCyber solves this gap at PKR 45,000/year — 97% cheaper — with Pakistan-first detection built in.

### Current State

| Dimension | Status |
|-----------|--------|
| Core Product (MVP) | ✅ Complete — pitch ready |
| Authentication & Security | ✅ Production ready |
| Billing & Local Payments | ✅ Safepay + JazzCash integrated |
| DLP Detection Engine | ✅ 40+ rule categories live |
| LLM-aware DLP Pipeline | ✅ Pre/post scan pipeline live |
| Scheduled Scans | ✅ Complete |
| Alert System | ✅ Email + Telegram + WebSocket |
| Report Export | ✅ CSV / HTML / JSON |
| UI / Dashboard | ✅ Mobile responsive |
| Test Coverage | ⚠️ ~60% — needs improvement |
| Background Workers (Celery) | ❌ Not yet automated |
| SMTP Email (password reset) | ❌ Development mode only |

**Overall Verdict**: Production-ready for pilot customers and small business sales. Enterprise-hardening planned for Month 4–6.

### Ask

Raising **PKR 15,000,000 (~$53,000 USD)** pre-seed to hire two engineers, complete PDPA certification, execute go-to-market, and reach PKR 3.5M ARR within 12 months.

---

## 2. Product Overview

### 2.1 What Is MyCyber?

MyCyber is a self-hostable, open-source Data Loss Prevention platform built for organisations that cannot afford to lose sensitive data. The platform provides a single, unified control plane for:

- **File Scanning** — Detect PII in uploaded documents (PDF, DOCX, CSV, TXT, JSON, XML, EML, logs)
- **Text & API Payload Scanning** — Real-time inspection of text inputs, form submissions, and API call bodies
- **LLM DLP Pipeline** — Pre-scan user prompts before they reach Claude/GPT; post-scan LLM responses for data exfiltration
- **Scheduled Automated Scans** — Cron-based scan jobs with a management UI
- **Real-time Alerting** — WebSocket push, email notifications, and Telegram bot alerts
- **Compliance Reporting** — CSV, HTML (print-to-PDF), and JSON exports with severity filters

### 2.2 Scanning Pipeline

```
User uploads file / sends LLM prompt
         ↓
  Pre-scan (prompt injection check)
         ↓
  40+ DLP rule engine (regex + ML hybrid)
         ↓
  PII · Credentials · Financial · Malware
         ↓
  Risk Score 0–100 → Alert → Notify Admin
         ↓
  Post-scan LLM response check
         ↓
  Audit log + Report export
```

### 2.3 Detection Categories

| Category | Examples |
|----------|---------|
| Pakistani PII | CNIC (13-digit), 03XX phone numbers, local addresses |
| Financial Data | IBAN (PK format), credit card numbers, bank account numbers |
| Credentials | API keys, GitHub tokens, AWS/GCP access keys, JWT tokens |
| Secrets | Private keys, .env files, database connection strings |
| LLM Threats | Prompt injection, jailbreak attempts, data exfiltration via LLM response |
| Malware Indicators | YARA patterns, suspicious file signatures |
| Network Payloads | HTTP body inspection, form field scanning |

### 2.4 Plan Feature Matrix

| Feature | Free | Pro | Enterprise | Custom |
|---------|------|-----|------------|--------|
| Scans/month | 100 | 10,000 | Unlimited | Unlimited |
| Text + file scan | ✅ | ✅ | ✅ | ✅ |
| Network scan | ❌ | ✅ | ✅ | ✅ |
| Scheduled scans | ❌ | 5 jobs | Unlimited | Unlimited |
| API access | ❌ | ✅ | ✅ | ✅ |
| Email alerts | ✅ | ✅ | ✅ | ✅ |
| Telegram alerts | ❌ | ✅ | ✅ | ✅ |
| PDF/CSV reports | ❌ | ✅ | ✅ | ✅ |
| Real-time dashboard | ❌ | 30s refresh | Live WebSocket | Live WebSocket |
| Support | Community | Email (24h) | Dedicated Slack | On-call SLA |
| SLA | — | 99% uptime | 99.9% uptime | Custom |
| Multi-tenant / SSO | ❌ | ❌ | ✅ | ✅ |
| On-premise deploy | ❌ | ❌ | ❌ | Custom quote |
| PDPA compliance report | ❌ | ❌ | ✅ | ✅ |

---

## 3. Technical Architecture

### 3.1 Technology Stack

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| Frontend | React 18 + Vite + Tailwind CSS | Modern, responsive SPA; fast build times |
| API Backend | FastAPI (Python 3.11) | Async, high-performance REST + WebSocket |
| Authentication | JWT + Refresh Tokens + TOTP MFA + RBAC | Zero-trust, industry standard |
| Detection Engine | BERT NER + Regex Hybrid | ML precision + rule-based coverage |
| LLM Pipeline | Anthropic Claude API | LLM-aware DLP with pre/post scan |
| Database | PostgreSQL + SQLAlchemy + Alembic | Production-grade, migration-managed |
| Workers | Celery + Redis | Async/scheduled scan execution |
| Monitoring | Prometheus + Grafana + MLflow | Observability and ML tracking |
| Payments | Safepay + JazzCash + Easypaisa | Local payment methods |
| Infrastructure | Docker Compose / Kubernetes | Self-host or cloud; &lt;10 min deploy |

### 3.2 System Architecture Diagram

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
       │
┌──────▼───────────────────────────────────────────────┐
│  Monitoring: Prometheus + Grafana + MLflow            │
└──────────────────────────────────────────────────────┘
```

### 3.3 Security Architecture

MyCyber achieves an overall **security rating of 7.5/10** (Good) in internal static analysis:

**Strengths:**
- JWT authentication with bcrypt password hashing
- TOTP MFA (pyotp) with setup/verify/disable flows
- Account lockout after 5 failed attempts (15-minute lock)
- Rate limiting: 60 requests/minute per endpoint (Slowapi)
- SQLAlchemy ORM — parameterised queries, zero raw SQL
- Pydantic input validation on all endpoints
- Docker container isolation for all services
- HTTPS/TLS with HSTS, CSP, X-Frame-Options security headers
- CORS restricted to configured origins
- No `eval()`/`exec()` in codebase; no hardcoded secrets in FastAPI backend

**Pre-Production Fixes Required (High Priority):**
- Set `JWT_SECRET_KEY` to 32+ character random value (not default)
- Configure `CORS_ORIGINS` to production domain
- Set `APP_ENV=production` to disable debug mode
- Configure SMTP for password reset email delivery

**Enterprise-Grade Hardening (Phase 3):**
- Move to `httpOnly` cookies with CSRF protection
- Add WAF (Cloudflare/AWS WAF) for DDoS protection
- Enable per-user rate limiting (currently per-IP)
- Implement database SSL connection
- Conduct professional penetration test
- SOC-2 alignment documentation

### 3.4 Infrastructure Requirements

**Minimum (Pilot / Small Business):**
- 2 vCPU, 4 GB RAM, 20 GB SSD
- Docker + Docker Compose
- PostgreSQL 15+, Redis 7+

**Recommended (Production / Enterprise):**
- 4+ vCPU, 8 GB RAM, 50 GB SSD
- K8s cluster with horizontal pod autoscaling
- Managed PostgreSQL (AWS RDS / DigitalOcean Managed DB)
- Redis Cluster for high availability

---

## 4. Market Analysis

### 4.1 Global Context

The global Data Loss Prevention market was valued at approximately **$12.6 billion USD in 2026** and is projected to grow at 15% CAGR through 2030, driven primarily by:
- Explosion of AI/LLM usage in enterprises (new DLP surface area)
- Expanding data protection regulations worldwide
- Increasing frequency and cost of data breaches

### 4.2 Pakistan-Specific Market

**Regulatory Driver — PDPA 2023:**
Pakistan's Personal Data Protection Act creates a mandatory compliance market overnight. Organisations processing personal data must implement technical controls including DLP systems. Non-compliance penalties create urgency that pure sales pitches cannot.

**Serviceable Market:**

| Segment | Estimated Count | Annual DLP Budget Potential |
|---------|----------------|----------------------------|
| Law Firms + CAs | 50,000+ | PKR 4,500–15,000/mo |
| Private Clinics / Hospitals | 30,000+ | PKR 4,500/mo |
| Fintech / Payment Companies | 500+ | PKR 15,000–50,000/mo |
| E-commerce Companies | 3,000+ | PKR 15,000/mo |
| Mid-size Banks / NBFCs | 100+ | PKR 50,000+/mo |
| Telcos | 10+ | PKR 100,000+/mo |

**Conservative TAM Calculation:**
- 0.1% of 5.2M businesses × PKR 45,000/year = **PKR 234M/year**
- Including enterprise segment uplift: **PKR 280–400M/year TAM**

### 4.3 Competitive Analysis

| Competitor | Annual Cost (PKR) | CNIC/IBAN Rules | Local Payments | Self-Hostable | LLM DLP |
|-----------|------------------|-----------------|----------------|--------------|---------|
| Forcepoint DLP | PKR 1,100,000+ | ❌ | ❌ | Limited | ❌ |
| Symantec DLP | PKR 1,400,000+ | ❌ | ❌ | Limited | ❌ |
| Microsoft Purview | PKR 900,000+ | ❌ | ❌ | ❌ | Partial |
| Zscaler DLP | PKR 1,800,000+ | ❌ | ❌ | ❌ | Partial |
| **MyCyber DLP** | **PKR 45,000** | **✅** | **✅** | **✅** | **✅** |

**97% cost advantage. No direct competitor in the Pakistan-local DLP space.**

### 4.4 Defensibility

1. **Pakistan-first data patterns** — CNIC, IBAN, 03XX phone, Easypaisa patterns built into the rule engine. Replicating this requires deep local research.
2. **Open-core moat** — MIT core drives GitHub stars and community. Proprietary layers (compliance reports, LLM pipeline, rules DB) are not open-sourced.
3. **PDPA certification** — First mover to achieve certification creates a trust anchor that later entrants cannot shortcut.
4. **Local payment integration** — JazzCash/Easypaisa reduces friction for the 70% of Pakistani SMEs that don't have corporate credit cards.

---

## 5. Financial Model

### 5.1 Pricing Architecture

| Plan | Monthly Price | Annual Price | Savings | Target Segment |
|------|--------------|-------------|---------|---------------|
| Free | PKR 0 | — | — | Freelancers, lead magnet |
| Pro | PKR 4,500 | PKR 45,000 | 2 months free | SMEs, professional firms |
| Enterprise | PKR 15,000 | PKR 150,000 | 2 months free | Fintech, SaaS startups |
| Custom | PKR 50,000+ | Negotiated | Negotiated | Banks, telcos, large enterprises |

**Pricing Anchors:**
- US DLP tools: PKR 1,100,000+/year
- MyCyber Pro: PKR 45,000/year → "97% cheaper with Pakistan-native detection"
- Pro plan framing: "Less than PKR 125 per day" or "Cheaper than one client dinner per month"

### 5.2 Revenue Streams

1. **Subscription MRR** — Core SaaS plans (primary revenue stream, 70% of total)
2. **API Usage / Overage** — Per-scan metered billing above plan limits (15% of total)
3. **Professional Services** — On-premise deployment, custom rule development, integrations (10% of total)
4. **Compliance Add-ons** — PDPA readiness audit reports, annual compliance packages (5% of total)

### 5.3 Revenue Projections

#### Conservative Scenario (Base Case)

| Period | Pro Customers | Enterprise Customers | Custom Customers | Monthly Revenue | ARR |
|--------|--------------|---------------------|-----------------|----------------|-----|
| Month 1 | 0 | 0 | 0 | PKR 0 | PKR 0 |
| Month 2 | 5 | 0 | 0 | PKR 22,500 | PKR 270,000 |
| Month 3 | 10 | 1 | 0 | PKR 60,000 | PKR 720,000 |
| Month 6 | 30 | 3 | 0 | PKR 180,000 | PKR 2,160,000 |
| Month 9 | 50 | 5 | 1 | PKR 340,000 | PKR 4,080,000 |
| Month 12 | 50 | 5 | 1 | PKR 340,000+ | PKR 4,080,000+ |

#### Year 1 ARR Target: PKR 3,525,000

Breakdown:
- 50 Pro at PKR 45,000/year = PKR 2,250,000
- 5 Enterprise at PKR 150,000/year = PKR 750,000
- 1 Custom at PKR 600,000/year = PKR 600,000
- **Total ARR: PKR 3,600,000 (~$12,900 USD)**

### 5.4 Unit Economics

| Metric | Value | Notes |
|--------|-------|-------|
| ARPU (Pro) | PKR 4,500/mo | Pure subscription |
| ARPU (Enterprise) | PKR 15,000/mo | Subscription + API |
| Gross Margin (Pro) | ~60% | Infrastructure + support cost |
| Gross Margin (Enterprise) | ~70% | Higher margin from volume |
| CAC (SME direct) | ~PKR 5,000 | LinkedIn + referral |
| CAC (Enterprise inbound) | ~PKR 25,000 | Sales + demo cycle |
| LTV (Pro, 18-month churn) | PKR 81,000 | 18-month avg retention |
| LTV/CAC (Pro) | ~16x | Healthy ratio |
| Payback Period (Pro) | ~1.1 months | Very fast payback |

### 5.5 Cost Structure

**Fixed Monthly Costs (Post-Launch):**
| Item | Monthly Cost |
|------|-------------|
| VPS / Cloud Infrastructure | PKR 15,000–25,000 |
| Anthropic Claude API (LLM scans) | PKR 8,000–20,000 |
| VirusTotal API | Free tier initially |
| SMTP (Mailgun/SendGrid) | PKR 2,000 |
| Domain + SSL | PKR 500 |
| Monitoring (self-hosted Grafana) | PKR 0 |
| **Total Fixed** | **~PKR 26,000–48,000/mo** |

**Break-even:** ~6–11 Pro customers (before salaries). Cash-flow positive on subscriptions alone very early.

### 5.6 Funding Needs & Burn Rate

With PKR 15M raised and 2 engineer hires at PKR 150,000/mo each:
- Monthly burn: ~PKR 600,000 (salaries + infra + marketing)
- Runway: ~25 months at zero revenue
- Expected self-sustaining: Month 8–10 (50 Pro + 3 Enterprise customers)

---

## 6. Intellectual Property & Rights Management

### 6.1 Licensing Model

MyCyber follows an **Open Core** licensing strategy — a proven model used by GitLab, Elastic, HashiCorp, and others. The MIT-licensed core drives adoption; the proprietary layers create commercial moat.

#### Core (MIT License)

The following components are open-source under the MIT License:
- DLP engine core framework (regex pipeline, risk scoring, alert dispatch)
- FastAPI backend framework and routing structure
- React dashboard UI and component library
- PostgreSQL database schema and Alembic migrations
- Docker Compose deployment configuration
- GitHub Actions CI/CD workflows

**Rights granted under MIT:**
- Free to use, copy, modify, merge, publish, distribute
- Free to use in commercial products
- No warranty — use at own risk
- Attribution required (copyright notice must be preserved)

#### Proprietary Layers

The following components are **not** open-sourced and are exclusively licensed to paying customers:

| Component | License Type | Access |
|-----------|-------------|--------|
| Pakistan PII Rule Database (CNIC, IBAN, 03XX, Easypaisa patterns) | Proprietary SaaS | Pro + Enterprise + Custom |
| LLM DLP Pre/Post Scan Pipeline | Proprietary SaaS | Enterprise + Custom |
| BERT NER model weights (trained on Pakistani PII datasets) | Trade Secret / Internal | Backend only |
| Prompt Injection Signature Database | Trade Secret | Backend only |
| PDPA Compliance Report Templates | Proprietary | Enterprise + Custom |
| Safepay/JazzCash billing integration | Proprietary | Internal use |
| Multi-tenancy isolation layer | Proprietary | Custom only |

### 6.2 Copyright

All original source code is Copyright © 2026 Feroz U Din and MyCyber Project Contributors.

Contributors retain copyright on their specific contributions but grant MyCyber an irrevocable, royalty-free license to use, modify, and sublicense those contributions under the Contributor License Agreement (CLA) on GitHub.

**Copyright registration:** Planned with the Pakistan Intellectual Property Organisation (IPO) and NUTECH's research IP registry in Q3 2026.

### 6.3 Trademark

The names "MyCyber", "MyCyber DLP", and the MyCyber shield logo are claimed trademarks of Feroz U Din.

**Trademark registration status:**
- Pakistan (IPO-Pakistan): Filing planned Q3 2026. Estimated cost: PKR 15,000–25,000.
- Once registered, the ® mark will be used on all commercial materials.
- International trademarks (USPTO, EUIPO) planned post-Series A.

**Usage policy:**
- Contributors and users of the MIT core may reference "MyCyber" for attribution purposes.
- Commercial use of the "MyCyber" brand on competing DLP products is prohibited.
- OEM / white-label use of the platform requires a separate Brand License Agreement.

### 6.4 Domain & Digital Assets

| Asset | Status |
|-------|--------|
| mycyber.pk | Target domain — acquisition pending |
| github.com/Khan-Feroz211/MyCyber-Project | Active (public repository) |
| Social media handles @MyCyberPK | Reservation recommended |

### 6.5 Third-Party License Obligations

MyCyber depends on open-source components. Key licenses and obligations:

| Dependency | License | Commercial Use |
|-----------|---------|---------------|
| FastAPI | MIT | ✅ Free |
| React | MIT | ✅ Free |
| SQLAlchemy | MIT | ✅ Free |
| Pydantic | MIT | ✅ Free |
| Celery | BSD | ✅ Free |
| Anthropic Python SDK | MIT | ✅ Free (API costs apply) |
| PyOTP (TOTP MFA) | MIT | ✅ Free |
| Tailwind CSS | MIT | ✅ Free |
| Prometheus Client | Apache 2.0 | ✅ Free |
| bcrypt | Apache 2.0 | ✅ Free |

No GPL or AGPL dependencies are present that would require open-sourcing proprietary layers. This is intentional and must be maintained in the dependency policy.

### 6.6 Data Rights & PDPA Compliance

**Customer data:**
- Scan content is **never stored in plain text** — results are stored as metadata (severity, category, risk score)
- Actual PII found in scans is hashed/redacted in the database
- Customers own their data entirely; MyCyber has no analytics rights over scan content
- Data residency: The self-hosted model allows Pakistani customers to keep all data within Pakistan's borders (critical for PDPA compliance)

**PDPA certification:**
- Requires engagement with a PDPA-registered consultant. Estimated cost: PKR 80,000–150,000
- Certification expected Q3 2026 — enables explicit "PDPA-ready" marketing claims
- Post-certification, MyCyber Enterprise includes a signed PDPA Readiness Statement for customers

### 6.7 Contributor License Agreement (CLA)

All external contributors (beyond founding team) must sign a CLA before any pull request is merged. The CLA:
- Confirms the contributor owns the code they're contributing
- Grants MyCyber a license to use contributions in both the open-source MIT release and the proprietary commercial build
- Does not transfer copyright away from the contributor

The CLA is hosted on GitHub and enforced via the CLA-bot GitHub Action.

---

## 7. Go-to-Market Strategy

### 7.1 GTM Philosophy

MyCyber uses a **Product-Led Growth (PLG)** motion at the bottom of the market (freelancers → SMEs) combined with a **Sales-Led** motion at the top (fintech, banks). This allows viral adoption without a large sales team early on, while preserving the ability to close high-value enterprise deals through direct relationship management.

### 7.2 GTM by Segment

#### Segment 1: Freelancers / Micro-Businesses → Viral Free Tier

**Trigger:** Client asks "How do you protect my data?"

**Tactic:**
1. Register on Free plan (no credit card)
2. Paste client's spreadsheet → screenshot CNIC/IBAN hits → share on LinkedIn/X
3. The screenshot becomes organic content; employers of those freelancers discover MyCyber
4. Upgrade trigger: "You've hit 100 scans/month — upgrade to Pro for PKR 4,500 to keep scanning"

**Cost:** Zero. **Target:** 500 Free users by Month 3.

#### Segment 2: Law Firms / CAs / Clinics → Direct Outreach

**Pain:** Patient/client CNICs leaked in email attachments = PDPA liability + reputational risk.

**Outreach channel:** LinkedIn → managing partners, practice managers, clinic administrators.

**Pitch:** "For the price of one dinner with a client, you can prove to regulators that you have data-leak controls."

**Close tactic:**
- Annual plan PKR 45,000 = less than PKR 125/day
- First 3 months at 50% off in exchange for a testimonial
- Offer a 30-minute live demo over Google Meet

**Target:** 10 Pro customers by Month 3. **MRR contribution:** PKR 45,000.

#### Segment 3: Fintech / SaaS Startups → Compliance Wedge

**Pain:** Enterprise buyers demand SOC-2 / security questionnaire answers during due diligence. No DLP = deal delayed or lost.

**Pitch:** "MyCyber gives you a live security dashboard you can screenshare in a buyer call."

**Close tactic:**
- Pilot program: "Pay after 30 days only if your compliance officer approves the report"
- Enterprise plan (PKR 15,000/mo) includes API access to embed scanning into their own product pipeline
- Attend Y Combinator / Disrupt / LUMS alumni fintech events for warm introductions

**Target:** 3 Enterprise customers by Month 5. **MRR contribution:** PKR 45,000.

#### Segment 4: Banks / Telcos / Large Enterprises → Partnership Channel

**Approach:** Do NOT cold-pitch directly. Enter through:
- SECP-registered IT resellers and system integrators (20% revenue share)
- Big 4 consulting firm IT advisory practices (co-sell arrangement)
- PDPA workshops and SECP compliance events (thought leadership / speaking)

**Offering:** White-label option + on-premise deployment + custom SLAs + dedicated support.

**Target:** 1 Custom contract (PKR 600K+/year) by Month 9.

### 7.3 Channel Mix & Budget

| Channel | Monthly Budget | Expected Leads/mo | Cost per Lead |
|---------|--------------|------------------|--------------|
| GitHub / OSS community | Free | 50–100 | PKR 0 |
| LinkedIn outreach (organic) | Free | 20–40 | PKR 0 |
| Tech meetups (Lahore, Karachi, Islamabad) | PKR 10,000 | 10–20 | PKR 500–1,000 |
| SECP / PDPA compliance workshops | Free (speaking) | 30–50 | PKR 0 |
| IT Reseller partner channel | 20% rev share | 5–10 enterprise | Variable |
| Google Ads (Urdu + English) | PKR 20,000 | 30–60 | PKR 333–667 |
| **Total Marketing Budget (Month 1–3)** | **PKR 30,000/mo** | **145–270** | **avg PKR 110** |

### 7.4 Tactical Pricing Rules

1. **Always anchor against foreign cost** — "US tools cost PKR 1.1M/year. We cost PKR 45,000."
2. **Annual pre-pay is king** — 2 free months on annual = cash flow positive early. Push every Pro conversation to annual.
3. **Pilot pricing** — first enterprise customer gets 50% off for 3 months in exchange for a public case study.
4. **Never discount the monthly** — if they want cheaper, push to annual. Monthly churn risk is real.
5. **Add seats, not plan downgrades** — after 10 users, Enterprise adds PKR 1,500/user/month. Volume = revenue growth without plan proliferation.
6. **JazzCash / Easypaisa from day one** — 70% of Pakistani SMEs don't have corporate cards. Friction kills conversions.

### 7.5 Content & Community Strategy

- **GitHub README & Demo GIF** — Best ROI content. Target 200+ GitHub stars in first 3 months via HackerNews and Pakistani dev Slack/Discord communities.
- **PDPA explainer blog posts** — SEO-targeted "How to comply with PDPA 2023 in Pakistan" content. Drives inbound from compliance-anxious business owners.
- **LinkedIn case studies** — After first pilot customers: "How [Law Firm X] detected 47 CNIC leaks in one week using MyCyber."
- **Telegram channel** — For community support, updates, and product feedback. Low cost, high trust for Pakistani audience.

---

## 8. Operations Plan

### 8.1 Deployment Options

| Mode | Description | Target Customer |
|------|-------------|----------------|
| SaaS Cloud (hosted by MyCyber) | Managed, no infra required | Free, Pro customers |
| Self-hosted (Docker Compose) | Customer deploys on their own server | Pro, Enterprise (data residency needs) |
| On-premise (custom) | Fully air-gapped deployment | Custom / Enterprise banks |

### 8.2 SLA Commitments

| Plan | Uptime SLA | Support Response | Escalation |
|------|-----------|-----------------|-----------|
| Free | No SLA | Community forum | — |
| Pro | 99% monthly | Email, 24h | — |
| Enterprise | 99.9% monthly | Dedicated Slack, 4h | On-call engineer |
| Custom | Negotiated (99.95%+) | Dedicated account manager | 1h P1 SLA |

### 8.3 Support Infrastructure

- **Tier 1:** Telegram community group + GitHub Issues (Free plan)
- **Tier 2:** Email support with Freshdesk ticketing (Pro)
- **Tier 3:** Dedicated Slack channel (Enterprise)
- **Tier 4:** On-call WhatsApp line + dedicated account manager (Custom)

### 8.4 Data Operations

**Backup Policy:**
- PostgreSQL: Daily automated backups, 30-day retention
- Redis: RDB persistence, hourly snapshots
- Encryption keys: Stored in separate secret management system (not in DB backup)

**Incident Response:**
- P1 (data breach risk): 1-hour SLA for Enterprise/Custom, 4-hour for Pro
- P2 (service degradation): 4-hour SLA for Enterprise, 24-hour for Pro
- P3 (feature request): Next sprint cycle

---

## 9. Risk Management

### 9.1 Technical Risks

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|-----------|
| Data breach of customer scan data | Low | Critical | AES-256 encryption at rest; minimal PII retention; self-host option |
| LLM API cost overrun (Claude) | Medium | High | Rate limiting per plan; caching; fallback to regex-only mode |
| PostgreSQL performance under load | Medium | Medium | Connection pooling (already configured); horizontal read replicas planned |
| False negative in CNIC/IBAN detection | Low | High | Ongoing rule validation; ML + regex hybrid; community rule submissions |
| Background worker failures (Celery) | Medium | Medium | Dead letter queue; retry logic; monitoring alerts |

### 9.2 Business Risks

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|-----------|
| Large competitor enters PK market | Low (18-24 months) | High | PDPA cert + local payments + community moat are 18-month leads |
| PDPA enforcement delayed | Medium | Medium | Compliance fear still drives sales; enforcement adds urgency but isn't required |
| Customer churn (SME instability) | Medium | Medium | Annual pre-pay reduces churn; enterprise anchor customers stabilise MRR |
| Key man risk (founding team) | Medium | High | Hire second engineer in Phase 1; document all architecture |
| Payment gateway failure (Safepay) | Low | High | JazzCash as backup; bank transfer fallback |

### 9.3 Legal & Compliance Risks

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|-----------|
| PDPA audit of MyCyber itself | Low | High | Implement data minimisation; get PDPA certification proactively |
| Third-party IP claim on detection rules | Very Low | Medium | Original rule authorship; no lifted datasets |
| Customer misuse of platform | Low | Medium | ToS clearly prohibiting illegal surveillance; RBAC controls |
| Trademark conflict on "MyCyber" name | Low | Medium | File trademark quickly; domain acquisition |

---

## 10. Roadmap

### Phase 1: Soft Launch (Now → 2 Weeks)

**Goal: First 50 users. Zero critical bugs. First paying customer.**

Technical:
- [ ] Fix SMTP email for password reset (4 hours — critical blocker)
- [ ] Set strong `JWT_SECRET_KEY` in production (1 hour)
- [ ] Configure `CORS_ORIGINS` to production domain (30 minutes)
- [ ] Add Celery background worker for scheduled scan automation (2 days)
- [ ] Deploy to production VPS (2 hours)
- [ ] Enable HTTPS with Let's Encrypt (1 hour)

Business:
- [ ] Register mycyber.pk domain
- [ ] Create LinkedIn company page
- [ ] Post launch announcement on NUTECH alumni network and Pakistani dev communities
- [ ] Create Telegram community channel
- [ ] Invite 20 beta testers from network

**Exit criteria:** 50 registered users, 0 P1 bugs, 1 paying Pro customer.

### Phase 2: Pilot Sales (Month 2–3)

**Goal: PKR 50,000 MRR. 5 Pro + 1 Enterprise paying customers. 2 case studies.**

Technical:
- [ ] Comprehensive test suite — target 80% coverage (5 days)
- [ ] Billing tests for Safepay edge cases (2 days)
- [ ] Performance testing under 100 concurrent users
- [ ] Remove legacy `app.py` Flask monolith files
- [ ] Redis session caching activated
- [ ] Database connection pooling tuned

Business:
- [ ] Approach 20 law firms / CAs via LinkedIn
- [ ] Approach 5 fintech startups at Lahore/Karachi events
- [ ] Begin PDPA certification process (retain legal consultant)
- [ ] File trademark application with IPO-Pakistan
- [ ] Create security whitepaper (2,000-word PDF)
- [ ] Publish 3 PDPA compliance blog posts for SEO

**Exit criteria:** 5 Pro + 1 Enterprise customers, PKR 50K MRR, 2 signed case studies.

### Phase 3: Enterprise Hardening (Month 4–6)

**Goal: 1 Enterprise contract PKR 50K+/month. Enterprise-ready product.**

Technical:
- [ ] SSO / SAML 2.0 integration (for enterprise login)
- [ ] Multi-tenancy org isolation (separate data per organisation)
- [ ] On-premise deployment guide + Helm charts for K8s
- [ ] Professional security penetration test
- [ ] SOC-2 alignment documentation
- [ ] httpOnly cookie auth (replace localStorage JWT)
- [ ] WAF configuration (Cloudflare)

Business:
- [ ] PDPA certification complete — announce publicly
- [ ] Hire DevOps engineer (monitoring, SLA, HA setup)
- [ ] Approach 3 SECP-registered fintechs directly
- [ ] Engage 2 IT reseller partners
- [ ] Publish penetration test summary report
- [ ] Target one Big 4 advisory firm co-sell arrangement

**Exit criteria:** 1 Enterprise deal PKR 600K+/year signed, PDPA certified, pen test complete.

### Phase 4: Scale (Month 7–12)

- GPU-accelerated BERT inference for high-throughput enterprise scanning
- Urdu PII detection model (expand to Urdu-language documents)
- Mobile companion app (React Native) for admin alerts
- Distributed scanning architecture (K8s + horizontal scaling)
- Cloud-hosted SaaS option (MyCyber Cloud) alongside self-hosted
- Series A fundraise preparation

---

## 11. Team

### Founding Team

**Feroz U Din (Feroz Khan)** — Founder & Lead Engineer
- Full-stack developer specialising in Python (FastAPI), React, security engineering, and ML-powered detection systems
- Designed the full system architecture: backend, LLM pipeline, billing, security middleware
- Contact: f24605023@nutech.edu.pk · GitHub: Khan-Feroz211
- Institution: NUTECH, Islamabad (National University of Technology)

**Sayyad Ali Naqi Naqvi** — Co-Founder, Security Systems
- Security systems design, DLP rule engine architecture

**Hasnain Ali** — Co-Founder, Backend Infrastructure
- Database modeling, backend services, API design

**Hassan Nasser** — Co-Founder, System Integration
- System monitoring, Linux integration layer, performance optimization

**Project inception:** December 2025, Version 1.0 (rule-based engine)
**Current version:** Post-refinement MVP with full AI/ML hybrid engine (June 2026)

### Advisory Needs (Actively Seeking)

| Role | Why Needed |
|------|-----------|
| PDPA Legal Consultant | Certification pathway, compliance advisory |
| Cybersecurity Advisor (CISSP/CISM) | Enterprise sales credibility, pen-test scoping |
| Pakistan VC/Angel Advisor | Warm introductions to Sarmayacar, i2i, Karandaaz |
| Enterprise Sales Advisor | Bank and telco relationship access |

### Hiring Plan (Post-Funding)

| Role | Month | Package | Priority |
|------|-------|---------|---------|
| Backend / Security Engineer | Month 1–2 | PKR 150,000/mo | 🔴 Critical |
| ML Engineer (NLP/NER) | Month 3–4 | PKR 150,000/mo | 🔴 Critical |
| DevOps Engineer | Month 4–5 | PKR 120,000/mo | 🟡 High |
| Sales / BD Lead | Month 5–6 | PKR 100,000/mo + commission | 🟡 High |

---

## 12. Funding & Investment Structure

### 12.1 Current Funding Status

Self-funded to date. All infrastructure built by the founding team during academic work at NUTECH. No external capital raised to date.

### 12.2 The Ask

**Round:** Pre-Seed  
**Amount:** PKR 15,000,000 (~$53,000 USD)  
**Structure:** Convertible note or SAFE preferred (simple, low legal cost)  
**Valuation cap:** PKR 75,000,000 (~$268,000 USD) pre-money  
**Discount:** 20% on conversion to Series A

### 12.3 Use of Funds

| Category | Amount (PKR) | % | Timeline |
|----------|-------------|---|---------|
| Engineering hires (2 × 6 months) | 7,200,000 | 48% | Month 1 onwards |
| PDPA Certification + Legal (IP + ToS + CLA) | 1,500,000 | 10% | Month 2–3 |
| Sales & Marketing (events, ads, content) | 2,100,000 | 14% | Month 1 onwards |
| Cloud Infrastructure (12-month commitment) | 1,200,000 | 8% | Month 1 |
| Trademark + IP Filings (PK + International) | 500,000 | 3% | Month 2 |
| Security Penetration Test | 800,000 | 5% | Month 4 |
| Working Capital / Reserve | 1,700,000 | 11% | Ongoing |
| **Total** | **15,000,000** | **100%** | — |

### 12.4 Investor Profiles & Terms

**Angel Investors (PKR 500K–5M each):**
- 5–8% equity for total PKR 5–7M
- Convertible note with 20% discount at Series A
- Board observer seat (optional)
- Monthly investor update email
- Pro-rata rights on Series A

**Pre-Seed Funds (Sarmayacar, i2i Ventures, Karandaaz Innovation Fund):**
- 10–15% equity for full PKR 15M round
- Pro-rata rights
- Quarterly board meetings
- Monthly KPI dashboard (MRR, churn, DAU)
- Information rights

**Strategic Partners (Revenue Share, No Equity):**
- IT resellers: 20% revenue share on referred customers
- PDPA consultants: Referral fee per compliance engagement
- Big 4 co-sell: Negotiated revenue share

### 12.5 Milestones for Investors

| Milestone | Timeline | What It Proves |
|-----------|---------|----------------|
| First paying Pro customer | Month 1 | Product-market fit exists |
| PKR 50,000 MRR | Month 3 | Repeatable sales motion |
| PDPA certification | Month 5 | Defensible enterprise moat |
| PKR 300,000 MRR | Month 6 | Scalable growth |
| First enterprise deal (PKR 50K+/mo) | Month 8–9 | Enterprise-readiness |
| PKR 3.5M ARR | Month 12 | Series A readiness (Sarmayacar benchmark) |

### 12.6 Exit Considerations

**Strategic acquisition targets (3–5 year horizon):**
- Regional cybersecurity firms expanding into Pakistan (e.g., Group-IB, Kaspersky MENA)
- Pakistani banks building internal security products
- Global DLP vendors wanting local presence (Forcepoint, Netskope)
- Cloud providers entering the Pakistan market (AWS, Google Cloud)

**IPO consideration:** Pakistan Stock Exchange tech listings are rare but growing. At PKR 50M+ ARR, a PSX listing or secondary market sale to a PE firm is a realistic exit path.

---

## Appendices

### A. Key Performance Indicators (Monthly Tracking)

| KPI | Target (Month 6) | Target (Month 12) |
|-----|-----------------|------------------|
| MRR | PKR 300,000 | PKR 340,000+ |
| ARR | PKR 3,600,000 | PKR 4,080,000+ |
| Registered Users | 500+ | 2,000+ |
| Paying Customers (Pro) | 30+ | 50+ |
| Enterprise Customers | 3+ | 5+ |
| Monthly Churn Rate | &lt;5% | &lt;3% |
| NPS Score | 40+ | 50+ |
| GitHub Stars | 500+ | 1,500+ |
| Avg Scans/Day | 5,000+ | 25,000+ |

### B. Regulatory & Compliance Checklist

- [ ] PDPA 2023 compliance assessment complete
- [ ] PDPA certification obtained (Q3 2026)
- [ ] Trademark registered with IPO-Pakistan
- [ ] Contributor License Agreement published on GitHub
- [ ] Privacy Policy + Terms of Service (reviewed by counsel)
- [ ] Data Processing Agreement template (for enterprise customers)
- [ ] GDPR alignment (for any EU-based customers accessing the SaaS)

### C. Contact & Resources

| Resource | Detail |
|----------|--------|
| Technical Lead | f24605023@nutech.edu.pk |
| GitHub Repository | github.com/Khan-Feroz211/MyCyber-Project |
| Security Disclosure | f24605023@nutech.edu.pk (48h response SLA) |
| Institution | NUTECH, Islamabad, Pakistan |

---

*This document is confidential and intended for potential investors, partners, and advisors only. Figures marked as projections or estimates are based on internal modelling and are not guaranteed.*

*Copyright © 2026 Feroz U Din — MyCyber Project. All rights reserved.*
