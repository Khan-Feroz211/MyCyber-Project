# MyCyber DLP Helm Chart

MyCyber DLP is an open-source Data Loss Prevention platform. This Helm chart
deploys the backend API, frontend SPA, PostgreSQL, Redis, and optional ingress
to Kubernetes.

## Prerequisites

- Kubernetes 1.21+
- Helm 3.8+
- A working container registry (or use the public `ghcr.io` images)

## Installation

```bash
# Add the chart from the local path
helm install mycyber ./helm/mycyber-dlp \
  --set postgresql.auth.password=$(openssl rand -hex 16) \
  --set env.JWT_SECRET_KEY=$(openssl rand -hex 24) \
  --set env.ENCRYPTION_MASTER_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
```

## Values

| Key | Type | Default | Description |
|---|---|---|---|
| `replicaCount` | int | `2` | Number of backend replicas |
| `image.repository` | str | `ghcr.io/khan-feroz211/mycyber-project/backend` | Backend image |
| `image.tag` | str | `latest` | Image tag |
| `postgresql.enabled` | bool | `true` | Deploy a PostgreSQL sub-chart |
| `redis.enabled` | bool | `true` | Deploy Redis |
| `env.JWT_SECRET_KEY` | str | — | **Required.** Min 32 chars |
| `env.ENCRYPTION_MASTER_KEY` | str | — | **Required.** 32-byte key |
| `ingress.enabled` | bool | `false` | Enable ingress |
| `resources.limits.cpu` | str | `1000m` | CPU limit |
| `resources.limits.memory` | str | `1Gi` | Memory limit |

## Health & Readiness Probes

Each service exposes:
- **Liveness probe** → `GET /health` (HTTP 200)
- **Readiness probe** → `GET /health` (HTTP 200, checks DB connectivity)

The backend `/health` endpoint returns `"degraded"` if the database is unreachable,
causing the readiness probe to fail and the pod to be removed from the service endpoints.
