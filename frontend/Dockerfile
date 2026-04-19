# =============================================================================
# MyCyber DLP — Frontend Dockerfile
# Multi-stage build: Node builds static assets, nginx serves them
# =============================================================================

# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files first for better layer caching
COPY package*.json ./

RUN npm ci --silent

# Copy the rest of the source and build
COPY . .

RUN npm run build


# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM nginx:alpine AS runtime

# Copy built static assets
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy nginx site configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1/health || exit 1

CMD ["nginx", "-g", "daemon off;"]
