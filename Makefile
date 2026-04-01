# =============================================================================
# MyCyber DLP — Makefile
# Requires: Docker, Docker Compose
# =============================================================================

.PHONY: up down build logs logs-backend migrate shell-backend shell-db \
        reset prod-up prod-down help

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
