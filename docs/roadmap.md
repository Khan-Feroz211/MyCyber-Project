# MyCyber DLP Platform — 6-Month Startup Roadmap

## Month 1 — Microservices Refactor + Local Docker Compose

**Goal:** All 5 services running locally via docker-compose, end-to-end scan flow working.

### Sprint 1 (Weeks 1–2)
- [ ] Scaffold service directories with Dockerfiles and requirements
- [ ] Implement ingestion-service: `/events` endpoint, Redis queue push
- [ ] Implement ml-inference-service: heuristic classifier, `/scan` endpoint
- [ ] Wire services together with docker-compose.yml
- [ ] Manual end-to-end smoke test: POST to ingestion → scan queued → result returned

### Sprint 2 (Weeks 3–4)
- [ ] Implement policy-engine: rule evaluation loop consuming Redis
- [ ] Implement alert-service: Slack webhook dispatcher
- [ ] Implement dashboard-api skeleton: JWT auth, /api/v1/scans stub
- [ ] PostgreSQL schema migration (Alembic) for users and scan events
- [ ] Write unit tests for all 5 services (target ≥ 80% coverage)

**Milestone:** `docker-compose up` brings all 5 services up; full scan pipeline executes.

---

## Month 2 — MLOps Pipeline (DVC + MLflow + Evidently)

**Goal:** Reproducible training pipeline tracked in MLflow; drift monitoring live.

### Sprint 3 (Weeks 5–6)
- [ ] Label initial training dataset (≥500 samples, 4 classes: CLEAN / PII_LOW / PII_HIGH / SECRET)
- [ ] Implement DVC pipeline: preprocess → train → evaluate → register stages
- [ ] Run first training experiment; log to local MLflow server
- [ ] Validate F1 gate and model registry promotion flow

### Sprint 4 (Weeks 7–8)
- [ ] Integrate Evidently drift monitor against reference dataset
- [ ] Implement retrain_trigger.py; wire into CI (scheduled GitHub Actions)
- [ ] Document model card (inputs, outputs, class definitions, bias notes)
- [ ] Mount trained model into ml-inference-service container

**Milestone:** `dvc repro` produces promoted production model; drift monitor runs daily.

---

## Month 3 — Kubernetes Deployment + CI/CD Pipeline

**Goal:** All services deployed to a cloud-managed K8s cluster; CI/CD pipeline live.

### Sprint 5 (Weeks 9–10)
- [ ] Provision GKE/EKS/AKS cluster; create `mycyber-dlp` namespace
- [ ] Apply all K8s manifests (namespace, configmap, secrets, PVC, deployments)
- [ ] Configure HPA for ml-inference; verify autoscaling under load
- [ ] Configure GitHub Actions pipeline (lint → test → security → build → deploy)

### Sprint 6 (Weeks 11–12)
- [ ] Set up staging environment; deploy-staging job with smoke tests
- [ ] Configure production environment with manual approval gate
- [ ] Set up Prometheus + Grafana dashboards on cluster
- [ ] Set up OpenTelemetry collector → Jaeger for distributed tracing

**Milestone:** `git push origin main` triggers full CI/CD; services live on staging and prod.

---

## Month 4 — Security Hardening + Compliance

**Goal:** Platform passes OWASP Top 10 checklist; SOC2/GDPR readiness documented.

### Sprint 7 (Weeks 13–14)
- [ ] RBAC: enforce Admin/Analyst/Viewer roles across all endpoints
- [ ] API key management: generate, revoke, rotate with audit log
- [ ] TLS termination at ingress (cert-manager + Let's Encrypt)
- [ ] Secrets rotation procedure with Kubernetes Secrets + Vault integration

### Sprint 8 (Weeks 15–16)
- [ ] Bandit SAST + Trivy container scanning in CI; all HIGH/CRITICAL resolved
- [ ] GDPR: data subject deletion endpoint (`DELETE /api/v1/tenants/{id}/data`)
- [ ] SOC2 Type I readiness: access controls, encryption at rest, audit logging
- [ ] Penetration test (OWASP ZAP) against staging; fix findings

**Milestone:** Security audit report with zero Critical findings.

---

## Month 5 — Multi-Tenancy + SaaS Billing

**Goal:** Onboard paying customers; Stripe billing integrated.

### Sprint 9 (Weeks 17–18)
- [ ] Multi-tenant data isolation: every DB query scoped by `tenant_id`
- [ ] Tenant onboarding flow: sign-up → provisioning → first scan within 5 minutes
- [ ] Stripe integration: subscription tiers (Starter / Pro / Enterprise)
- [ ] Usage metering: count scans per tenant per billing period

### Sprint 10 (Weeks 19–20)
- [ ] Self-service dashboard: invite team members, manage API keys, view billing
- [ ] Webhooks for payment events (subscription created, past-due, cancelled)
- [ ] Customer-facing status page (Statuspage.io or custom)
- [ ] SLA monitoring: 99.9% uptime target with PagerDuty alerts

**Milestone:** First paying customer onboarded end-to-end without manual intervention.

---

## Month 6 — Investor-Demo Ready + Load Testing + Pen Test

**Goal:** Platform ready for Series A demo; validated under 10× expected load.

### Sprint 11 (Weeks 21–22)
- [ ] Load test with k6: 1000 concurrent scans, p99 < 500 ms
- [ ] Chaos engineering: kill individual pods, verify automatic recovery
- [ ] Professional pen test by external firm; fix all Critical/High findings
- [ ] Documentation: architecture diagrams, API reference, runbooks

### Sprint 12 (Weeks 23–24)
- [ ] Demo environment with pre-loaded realistic data (synthetic PII)
- [ ] Investor pitch deck technical appendix (architecture, metrics, security posture)
- [ ] One-click trial: Terraform template spins up full stack in < 10 minutes
- [ ] Public changelog and product roadmap page

**Milestone:** Investor demo runs flawlessly; load test results documented.
