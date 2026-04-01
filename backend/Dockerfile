# =============================================================================
# MyCyber DLP — Backend Dockerfile
# Multi-stage build: builder installs deps, runtime runs the app
# =============================================================================

# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# System packages required to compile psycopg2 / asyncpg C extensions
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --upgrade pip \
    && pip install --prefix=/install --no-cache-dir -r requirements.txt


# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TRANSFORMERS_CACHE=/tmp/hf_models \
    HF_HOME=/tmp/hf_models

# Runtime-only system packages (libpq for asyncpg, curl for healthcheck)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libpq-dev \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder stage
COPY --from=builder /install /usr/local

# Create a non-root user for security
RUN useradd -m -u 1001 appuser

# Copy application source (owned by appuser)
COPY --chown=appuser:appuser . .

# Pre-download the NER model so the container starts instantly
# (This layer is cached unless requirements.txt changes)
RUN python -c "\
from transformers import pipeline; \
pipeline('ner', model='dslim/bert-base-NER', \
aggregation_strategy='simple', device=-1)" || true

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
