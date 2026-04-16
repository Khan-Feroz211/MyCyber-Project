#!/bin/bash
set -euo pipefail

NAMESPACE="mycyber-dlp"
echo "=== MyCyber DLP Deployment ==="

# Check required env vars
REQUIRED=(
    POSTGRES_PASSWORD JWT_SECRET
    OPENAI_API_KEY CLAUDE_API_KEY
    GEMINI_API_KEY GRAFANA_PASSWORD
)
for var in "${REQUIRED[@]}"; do
    if [ -z "${!var:-}" ]; then
        echo "ERROR: $var is not set"
        exit 1
    fi
done

# Pull latest images
docker pull ghcr.io/khan-feroz211/mycyber-project/backend:latest
docker pull ghcr.io/khan-feroz211/mycyber-project/frontend:latest

# Apply namespace first
kubectl apply -f k8s/namespace.yaml

# Create/update secrets
kubectl create secret generic mycyber-secrets \
    --namespace=$NAMESPACE \
    --from-literal=POSTGRES_USER=postgres \
    --from-literal=POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
    --from-literal=JWT_SECRET="$JWT_SECRET" \
    --from-literal=OPENAI_API_KEY="$OPENAI_API_KEY" \
    --from-literal=CLAUDE_API_KEY="$CLAUDE_API_KEY" \
    --from-literal=GEMINI_API_KEY="$GEMINI_API_KEY" \
    --from-literal=GRAFANA_PASSWORD="$GRAFANA_PASSWORD" \
    --from-literal=SAFEPAY_SECRET_KEY="${SAFEPAY_SECRET_KEY:-}" \
    --dry-run=client -o yaml | kubectl apply -f -

# Apply all manifests
kubectl apply -f k8s/

# Wait for database to be ready
echo "Waiting for PostgreSQL..."
kubectl wait --for=condition=ready pod \
    -l app=postgres -n $NAMESPACE \
    --timeout=120s

# Run migrations
echo "Running migrations..."
kubectl exec -n $NAMESPACE \
    $(kubectl get pod -n $NAMESPACE \
        -l app=mycyber-backend \
        -o jsonpath='{.items[0].metadata.name}') \
    -- alembic upgrade head

# Wait for backend
echo "Waiting for backend..."
kubectl wait --for=condition=ready pod \
    -l app=mycyber-backend -n $NAMESPACE \
    --timeout=180s

echo "=== Deployment complete ==="
echo "App: https://mycyber.yourdomain.com"
echo "Grafana: https://grafana.mycyber.yourdomain.com"
kubectl get pods -n $NAMESPACE
