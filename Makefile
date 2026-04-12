# =============================================================================
# MyCyber DLP — Makefile
# Requires: Docker, Docker Compose
# =============================================================================

.PHONY: up down build logs logs-backend migrate shell-backend shell-db \
        reset prod-up prod-down \
        mlflow grafana prometheus \
        logs-mlflow logs-prometheus logs-grafana \
        monitoring-up monitoring-down \
        lint lint-fix security test test-cov ci-local \
        help

# ── Help ──────────────────────────────────────────────────────────────────────
help:
	@echo ""
	@echo "  MyCyber DLP — available make targets"
	@echo "  ────────────────────────────────────────────────────────────"
	@echo "  make up             Start all services (detached)"
	@echo "  make down           Stop all services"
	@echo "  make build          Rebuild all images (no cache)"
	@echo "  make logs           Follow logs for all services"
	@echo "  make logs-backend   Follow backend logs only"
	@echo "  make migrate        Run Alembic DB migrations"
	@echo "  make shell-backend  Open bash shell in backend container"
	@echo "  make shell-db       Open psql in postgres container"
	@echo "  make reset          Full reset: stop, delete volumes, rebuild"
	@echo "  make prod-up        Start production stack"
	@echo "  make prod-down      Stop production stack"
	@echo "  make monitoring-up  Start MLflow, Prometheus, Grafana"
	@echo "  make monitoring-down Stop MLflow, Prometheus, Grafana"
	@echo "  make mlflow         Open MLflow UI (http://localhost:5001)"
	@echo "  make prometheus     Open Prometheus UI (http://localhost:9090)"
	@echo "  make grafana        Open Grafana UI (http://localhost:3001)"
	@echo "  make logs-mlflow    Follow MLflow logs"
	@echo "  make logs-prometheus Follow Prometheus logs"
	@echo "  make logs-grafana   Follow Grafana logs"
	@echo "  ────────────────────────────────────────────────────────────"
	@echo "  make lint           Ruff + Black format check"
	@echo "  make lint-fix       Auto-fix ruff + black"
	@echo "  make security       Bandit SAST scan"
	@echo "  make test           Run pytest"
	@echo "  make test-cov       Run pytest with coverage (≥60%)"
	@echo "  make ci-local       Run full local CI simulation"
	@echo "  ────────────────────────────────────────────────────────────"
	@echo ""

# ── Development ───────────────────────────────────────────────────────────────
up:
	docker-compose up -d

down:
	docker-compose down

build:
	docker-compose build --no-cache

logs:
	docker-compose logs -f

logs-backend:
	docker-compose logs -f backend

migrate:
	docker-compose exec backend alembic upgrade head

shell-backend:
	docker-compose exec backend /bin/bash

shell-db:
	docker-compose exec postgres psql \
	  -U postgres \
	  -d mycyber_dlp

reset:
	docker-compose down -v
	docker-compose up -d --build

# ── Production ────────────────────────────────────────────────────────────────
prod-up:
	docker-compose -f docker-compose.prod.yml up -d

prod-down:
	docker-compose -f docker-compose.prod.yml down

# ── Monitoring ────────────────────────────────────────────────────────────────
monitoring-up:
	docker-compose up -d mlflow prometheus grafana

monitoring-down:
	docker-compose stop mlflow prometheus grafana

mlflow:
	@echo "Opening MLflow at http://localhost:5001"
	open http://localhost:5001 2>/dev/null || \
	  xdg-open http://localhost:5001

grafana:
	@echo "Opening Grafana at http://localhost:3001"
	open http://localhost:3001 2>/dev/null || \
	  xdg-open http://localhost:3001

prometheus:
	@echo "Opening Prometheus at http://localhost:9090"
	open http://localhost:9090 2>/dev/null || \
	  xdg-open http://localhost:9090

logs-mlflow:
	docker-compose logs -f mlflow

logs-prometheus:
	docker-compose logs -f prometheus

logs-grafana:
	docker-compose logs -f grafana

# ── Local CI / Dev tooling ────────────────────────────────────────────────────
lint:
	cd backend && ruff check app tests
	cd backend && black --check app tests

lint-fix:
	cd backend && ruff check app tests --fix
	cd backend && black app tests

security:
	cd backend && bandit -r app -c .bandit

test:
	cd backend && pytest tests/ -v

test-cov:
	cd backend && pytest tests/ -v \
	  --cov=app \
	  --cov-report=term-missing \
	  --cov-fail-under=60

ci-local:
	make lint
	make security
	make test-cov
	@echo "All CI checks passed locally"

