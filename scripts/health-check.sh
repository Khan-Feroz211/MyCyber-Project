#!/bin/bash
# =============================================================================
# MyCyber DLP — Post-Deployment Health Check
# Usage: ./scripts/health-check.sh [BASE_URL]
# Example: ./scripts/health-check.sh https://mycyber.yourdomain.com
# Run after every deployment to verify the stack is healthy.
# =============================================================================
set -euo pipefail

BASE_URL="${1:-https://mycyber.yourdomain.com}"
NAMESPACE="mycyber-dlp"
PASS=0; FAIL=0; WARN=0

pass() { echo "✅ $1"; PASS=$((PASS+1)); }
fail() { echo "❌ $1"; FAIL=$((FAIL+1)); }
warn() { echo "⚠️  $1"; WARN=$((WARN+1)); }

echo "=============================="
echo " MyCyber DLP Health Check"
echo " Target: $BASE_URL"
echo "=============================="
echo ""

# 1. K8s pods all running
echo "--- Kubernetes ---"
PODS=$(kubectl get pods -n "$NAMESPACE" \
    --no-headers 2>/dev/null | \
    grep -v "Running" | wc -l)
[ "$PODS" -eq 0 ] && pass "All K8s pods running" \
    || fail "Some pods not running ($PODS unhealthy)"

# 2. Backend health endpoint
echo ""
echo "--- API ---"
STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    "$BASE_URL/health" || echo "000")
[ "$STATUS" = "200" ] && pass "Backend health ok (HTTP $STATUS)" \
    || fail "Backend health failed: HTTP $STATUS"

# 3. Frontend loads
STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    "$BASE_URL/" || echo "000")
[ "$STATUS" = "200" ] && pass "Frontend loads (HTTP $STATUS)" \
    || fail "Frontend failed: HTTP $STATUS"

# 4. Database connectivity (via /health JSON response)
HEALTH=$(curl -sf "$BASE_URL/health" 2>/dev/null \
    | python3 -c \
    "import sys,json; \
     d=json.load(sys.stdin); \
     print(d.get('database','error'))" \
    2>/dev/null || echo "error")
[ "$HEALTH" = "ok" ] && pass "Database connected" \
    || fail "Database check returned: $HEALTH"

# 5. Public API endpoint (billing plans — no auth required)
STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    "$BASE_URL/api/v1/billing/plans" || echo "000")
[ "$STATUS" = "200" ] && pass "Plans API ok (HTTP $STATUS)" \
    || warn "Plans API returned: HTTP $STATUS"

# 6. Auth endpoint rejects unauthenticated scan request
STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST "$BASE_URL/api/v1/scan/text" \
    -H "Content-Type: application/json" \
    -d '{"text":"test","fast_mode":true}' || echo "000")
[ "$STATUS" = "401" ] && pass "Auth enforcement ok (scan requires JWT)" \
    || warn "Auth check on /scan/text returned: HTTP $STATUS (expected 401)"

# 7. HPA configured
echo ""
echo "--- Autoscaling ---"
HPA=$(kubectl get hpa -n "$NAMESPACE" \
    --no-headers 2>/dev/null | wc -l)
[ "$HPA" -gt 0 ] && pass "HPA configured ($HPA rule(s) found)" \
    || warn "No HPA found in namespace $NAMESPACE"

# 8. SSL certificate valid
echo ""
echo "--- TLS ---"
DOMAIN=$(echo "$BASE_URL" | sed 's|https://||;s|/.*||')
if echo "$BASE_URL" | grep -q "^https://"; then
    EXPIRY=$(echo | openssl s_client \
        -servername "$DOMAIN" \
        -connect "${DOMAIN}:443" \
        2>/dev/null | openssl x509 \
        -noout -enddate 2>/dev/null | \
        cut -d= -f2 || echo "unknown")
    [ "$EXPIRY" != "unknown" ] && \
        pass "SSL cert valid until: $EXPIRY" \
        || warn "SSL check failed — certificate may not be issued yet"
else
    warn "SSL check skipped (HTTP-only target)"
fi

# 9. Prometheus scraping the backend
echo ""
echo "--- Observability ---"
PROM_POD=$(kubectl get pod -n "$NAMESPACE" \
    -l app=prometheus \
    -o jsonpath='{.items[0].metadata.name}' \
    2>/dev/null || echo "")
if [ -n "$PROM_POD" ]; then
    PROM_UP=$(kubectl exec \
        -n "$NAMESPACE" "$PROM_POD" \
        -- wget -qO- \
        "localhost:9090/api/v1/query?query=up{job='mycyber-dlp-backend'}" \
        2>/dev/null | \
        python3 -c \
        "import sys,json; \
         d=json.load(sys.stdin); \
         v=d['data']['result']; \
         print(v[0]['value'][1] if v else '0')" \
        2>/dev/null || echo "0")
    [ "$PROM_UP" = "1" ] && \
        pass "Prometheus scraping backend (up=1)" \
        || warn "Prometheus scrape status: $PROM_UP (backend may still be starting)"
else
    warn "Prometheus pod not found in $NAMESPACE — check monitoring stack"
fi

# 10. MLflow accessible
MLFLOW_POD=$(kubectl get pod -n "$NAMESPACE" \
    -l app=mlflow \
    -o jsonpath='{.items[0].metadata.name}' \
    2>/dev/null || echo "")
if [ -n "$MLFLOW_POD" ]; then
    MLFLOW=$(kubectl exec \
        -n "$NAMESPACE" "$MLFLOW_POD" \
        -- wget -qO- \
        "localhost:5001/health" \
        2>/dev/null | grep -c "OK" || echo "0")
    [ "$MLFLOW" = "1" ] && pass "MLflow healthy" \
        || warn "MLflow /health did not return OK"
else
    warn "MLflow pod not found in $NAMESPACE — check monitoring stack"
fi

# 11. Resource usage summary
echo ""
echo "--- Resource Usage ---"
kubectl top pods -n "$NAMESPACE" \
    2>/dev/null || warn "kubectl top unavailable — metrics-server may not be ready"

echo ""
echo "=============================="
echo " Results: $PASS ✅  $WARN ⚠️   $FAIL ❌"
echo "=============================="
if [ "$FAIL" -eq 0 ]; then
    echo "🚀 Production deployment healthy!"
    exit 0
else
    echo "🔥 Issues found — check the ❌ items above"
    exit 1
fi
