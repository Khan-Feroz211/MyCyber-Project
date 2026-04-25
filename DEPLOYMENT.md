# MyCyber DLP — Production Deployment Guide

This guide covers deploying MyCyber DLP to production on various platforms.

---

## 📋 Prerequisites

Before deploying, ensure you have:

- ✅ Domain name (e.g., `mycyber.pk`)
- ✅ SMTP credentials (Gmail App Password or SendGrid API key)
- ✅ Safepay secret keys (for billing)
- ✅ Telegram bot token (optional, for alerts)
- ✅ PostgreSQL 16 database (or managed service)
- ✅ Redis 7 instance (or managed service)

---

## 🚀 Deployment Options

| Platform | Cost | Difficulty | Best For |
|----------|------|------------|----------|
| **Railway** | $5-20/mo | Easy | Quick start, small teams |
| **Render** | $7-25/mo | Easy | Simple deployment |
| **AWS Lightsail** | $10-40/mo | Medium | More control, AWS ecosystem |
| **DigitalOcean** | $6-24/mo | Medium | Simple, good documentation |
| **Pakistan VPS** (Nayatel/Storm) | PKR 3000-5000/mo | Medium | Local presence, lower latency |

---

## Option 1: Railway (Recommended for Quick Start)

### 1. Create Railway Account

1. Go to [railway.app](https://railway.app)
2. Sign up with GitHub
3. Create a new project

### 2. Deploy Backend

```bash
# Install Railway CLI
npm install -g @railway/cli

# Login
railway login

# Initialize project
cd backend
railway init

# Add PostgreSQL
railway add postgresql

# Add Redis
railway add redis

# Set environment variables
railway variables set JWT_SECRET_KEY=$(openssl rand -hex 32)
railway variables set APP_ENV=production
railway variables set DATABASE_URL=$DATABASE_URL
railway variables set REDIS_URL=$REDIS_URL
railway variables set SMTP_HOST=smtp.gmail.com
railway variables set SMTP_PORT=587
railway variables set SMTP_USERNAME=your-gmail@gmail.com
railway variables set SMTP_PASSWORD=your-app-password
railway variables set EMAIL_FROM=noreply@yourdomain.com
railway variables set FRONTEND_URL=https://yourdomain.railway.app
railway variables set SAFEPAY_SECRET_KEY=your-safepay-key
railway variables set SAFEPAY_WEBHOOK_SECRET=your-webhook-secret
railway variables set TELEGRAM_BOT_TOKEN=your-telegram-token
railway variables set TELEGRAM_DEFAULT_CHAT_ID=your-chat-id

# Deploy
railway up
```

### 3. Deploy Frontend

```bash
cd frontend
railway init

# Set build command
railway variables set BUILD_COMMAND=npm run build
railway variables set START_COMMAND=npm run preview

# Deploy
railway up
```

### 4. Run Database Migrations

```bash
# Open Railway shell
railway shell

# Run migrations
cd /app
alembic upgrade head
```

### 5. Configure Celery Workers

Railway doesn't natively support Celery. Use a separate Railway service:

```bash
# Create Celery worker service
railway add --name celery-worker

# Set command
railway variables set COMMAND=celery -A app.celery_app worker --loglevel=info

# Deploy
railway up
```

---

## Option 2: AWS Lightsail

### 1. Create Lightsail Instance

1. Go to AWS Lightsail console
2. Create instance: Ubuntu 22.04, 2GB RAM, 1 CPU ($10/mo)
3. Create static IP ($3/mo)
4. Configure DNS (Route 53) for your domain

### 2. Connect to Instance

```bash
ssh ubuntu@your-instance-ip
```

### 3. Install Docker & Docker Compose

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose
sudo apt install docker-compose -y

# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker
```

### 4. Clone Repository

```bash
git clone https://github.com/Khan-Feroz211/MyCyber-Project.git
cd MyCyber-Project
```

### 5. Configure Environment

```bash
cp .env.docker.example .env.docker
nano .env.docker
```

Set the following variables:

```bash
# Database
POSTGRES_USER=postgres
POSTGRES_PASSWORD=your-strong-password
POSTGRES_DB=mycyber_dlp

# Auth
JWT_SECRET_KEY=your-random-32-char-string

# Email
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_USERNAME=your-gmail@gmail.com
SMTP_PASSWORD=your-app-password
EMAIL_FROM=noreply@yourdomain.com
FRONTEND_URL=https://yourdomain.com

# Redis
REDIS_URL=redis://redis:6379/0

# Safepay
SAFEPAY_SECRET_KEY=your-safepay-key
SAFEPAY_WEBHOOK_SECRET=your-webhook-secret

# Telegram (optional)
TELEGRAM_BOT_TOKEN=your-telegram-token
TELEGRAM_DEFAULT_CHAT_ID=your-chat-id

# Production
APP_ENV=production
CORS_ORIGINS=https://yourdomain.com
```

### 6. Start Services

```bash
docker-compose up -d
```

### 7. Run Migrations

```bash
docker-compose exec backend alembic upgrade head
```

### 8. Configure Nginx (Reverse Proxy)

```bash
# Install Nginx
sudo apt install nginx -y

# Create Nginx config
sudo nano /etc/nginx/sites-available/mycyber
```

Add this configuration:

```nginx
upstream backend {
    server localhost:8000;
}

upstream frontend {
    server localhost:80;
}

server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;

    # Redirect to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com www.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    # Frontend
    location / {
        proxy_pass http://frontend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # Backend API
    location /api/ {
        proxy_pass http://backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Health check
    location /health {
        proxy_pass http://backend/health;
    }
}
```

### 9. Enable SSL with Let's Encrypt

```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx -y

# Get SSL certificate
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com

# Auto-renewal (already configured)
```

### 10. Start Celery Workers

```bash
# Start Celery worker
docker-compose exec backend celery -A app.celery_app worker --loglevel=info

# Start Celery beat (in another terminal)
docker-compose exec backend celery -A app.celery_app beat --loglevel=info
```

For production, add these as separate services in `docker-compose.yml`:

```yaml
celery_worker:
  build: ./backend
  command: celery -A app.celery_app worker --loglevel=info
  env_file: .env.docker
  depends_on:
    - redis
    - postgres

celery_beat:
  build: ./backend
  command: celery -A app.celery_app beat --loglevel=info
  env_file: .env.docker
  depends_on:
    - redis
    - postgres
  volumes:
    - celery_beat_data:/app/celerybeat
```

---

## Option 3: DigitalOcean

### 1. Create Droplet

1. Go to DigitalOcean console
2. Create droplet: Ubuntu 22.04, 2GB RAM, 1 CPU ($6/mo)
3. Add block storage for PostgreSQL data (optional)

### 2. Follow AWS Lightsail Steps

The deployment steps are the same as AWS Lightsail (steps 2-10 above), just use DigitalOcean instead.

---

## Option 4: Pakistan VPS (Nayatel/Storm)

### 1. Get VPS

Contact Naytel or Storm for a VPS in Pakistan:
- Recommended: 4GB RAM, 2 CPU cores
- Cost: PKR 3000-5000/month

### 2. Follow AWS Lightsail Steps

Same deployment process as AWS Lightsail.

---

## 🔧 Environment Variables Checklist

### Required for Production:

| Variable | Required? | Example |
|----------|-----------|---------|
| `JWT_SECRET_KEY` | 🔴 Critical | `openssl rand -hex 32` |
| `DATABASE_URL` | 🔴 Critical | `postgresql+asyncpg://user:pass@host:5432/db` |
| `REDIS_URL` | 🔴 Critical | `redis://redis:6379/0` |
| `APP_ENV` | 🔴 Critical | `production` |
| `CORS_ORIGINS` | 🔴 Critical | `https://yourdomain.com` |
| `SMTP_HOST` | 🔴 Critical | `smtp.gmail.com` |
| `SMTP_PORT` | 🔴 Critical | `587` |
| `SMTP_USERNAME` | 🔴 Critical | `your-gmail@gmail.com` |
| `SMTP_PASSWORD` | 🔴 Critical | Gmail App Password |
| `EMAIL_FROM` | 🔴 Critical | `noreply@yourdomain.com` |
| `FRONTEND_URL` | 🔴 Critical | `https://yourdomain.com` |
| `SAFEPAY_SECRET_KEY` | 🔴 Critical | From Safepay dashboard |
| `SAFEPAY_WEBHOOK_SECRET` | 🔴 Critical | From Safepay dashboard |

### Optional but Recommended:

| Variable | Purpose |
|----------|---------|
| `TELEGRAM_BOT_TOKEN` | Telegram alerts |
| `TELEGRAM_DEFAULT_CHAT_ID` | Default chat for alerts |
| `GRAFANA_USER` | Grafana admin user |
| `GRAFANA_PASSWORD` | Grafana admin password |

---

## 📧 SMTP Configuration

### Gmail (Recommended for Start)

1. Enable 2-Factor Authentication on your Gmail
2. Go to Google Account → Security → App Passwords
3. Generate new app password: "MyCyber DLP"
4. Use this 16-character password as `SMTP_PASSWORD`

```bash
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_USERNAME=your-gmail@gmail.com
SMTP_PASSWORD=your-16-char-app-password
```

### SendGrid (Alternative)

1. Create account at [sendgrid.com](https://sendgrid.com)
2. Verify sender domain
3. Get API Key

```bash
SENDGRID_API_KEY=SG.your-api-key
EMAIL_FROM=noreply@yourdomain.com
```

---

## 🤖 Telegram Bot Setup (Optional)

### 1. Create Bot

1. Open Telegram and search for `@BotFather`
2. Send `/newbot`
3. Follow instructions to create bot
4. Get your bot token

### 2. Get Chat ID

1. Search for `@userinfobot` on Telegram
2. Send any message
3. It will reply with your chat ID

### 3. Configure

```bash
TELEGRAM_BOT_TOKEN=your-bot-token
TELEGRAM_DEFAULT_CHAT_ID=your-chat-id
```

---

## 💳 Safepay Configuration

### 1. Get Safepay Account

1. Go to [safepay.pk](https://safepay.pk)
2. Create merchant account
3. Complete KYC verification

### 2. Get API Keys

1. Go to Merchant Dashboard → API Settings
2. Get `Secret Key`
3. Get `Webhook Secret`

### 3. Configure

```bash
SAFEPAY_SECRET_KEY=your-secret-key
SAFEPAY_WEBHOOK_SECRET=your-webhook-secret
```

### 4. Set Webhook URL

In Safepay dashboard, set webhook URL to:
```
https://yourdomain.com/api/v1/billing/webhook
```

---

## 🔒 Security Hardening

### 1. Firewall Configuration

```bash
# Allow SSH, HTTP, HTTPS
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

### 2. Fail2Ban for SSH

```bash
sudo apt install fail2ban -y
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

### 3. Automatic Updates

```bash
sudo apt install unattended-upgrades -y
sudo dpkg-reconfigure -plow unattended-upgrades
```

### 4. Database Security

- Change default PostgreSQL password
- Restrict PostgreSQL to localhost only
- Enable SSL for database connections

---

## 📊 Monitoring

### 1. Prometheus Metrics

Prometheus is already included in `docker-compose.yml`. Access at:
- Prometheus: `http://your-server:9090`
- Grafana: `http://your-server:3001`

### 2. Logs

View logs:

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f backend
docker-compose logs -f celery_worker
```

### 3. Health Checks

```bash
# Backend health
curl https://yourdomain.com/health

# Expected response: {"status": "ok"}
```

---

## 🔄 CI/CD (Optional)

### GitHub Actions for Automatic Deployment

Create `.github/workflows/deploy.yml`:

```yaml
name: Deploy to Production

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Deploy to server
        uses: appleboy/ssh-action@master
        with:
          host: ${{ secrets.SERVER_HOST }}
          username: ${{ secrets.SERVER_USER }}
          key: ${{ secrets.SSH_PRIVATE_KEY }}
          script: |
            cd /path/to/MyCyber-Project
            git pull origin main
            docker-compose pull
            docker-compose up -d
            docker-compose exec backend alembic upgrade head
```

Add secrets to GitHub repository settings:
- `SERVER_HOST`
- `SERVER_USER`
- `SSH_PRIVATE_KEY`

---

## 🚨 Troubleshooting

### Issue: Database Connection Failed

```bash
# Check PostgreSQL is running
docker-compose ps postgres

# Check logs
docker-compose logs postgres

# Restart
docker-compose restart postgres
```

### Issue: Redis Connection Failed

```bash
# Check Redis
docker-compose ps redis

# Check logs
docker-compose logs redis

# Restart
docker-compose restart redis
```

### Issue: Celery Workers Not Running

```bash
# Check worker status
docker-compose ps celery_worker

# View logs
docker-compose logs celery_worker

# Restart
docker-compose restart celery_worker celery_beat
```

### Issue: SSL Certificate Error

```bash
# Renew certificate
sudo certbot renew

# Reload Nginx
sudo systemctl reload nginx
```

---

## 📈 Scaling

### When to Scale Up

- More than 100 concurrent users
- Database CPU > 70%
- Response times > 2s

### Scaling Options

1. **Horizontal Scaling**: Add more Docker containers
2. **Database**: Use managed PostgreSQL (AWS RDS, DigitalOcean Managed DB)
3. **Redis**: Use managed Redis (ElastiCache, DigitalOcean Managed Redis)
4. **Load Balancer**: Use AWS ALB or Nginx load balancer

---

## 💰 Cost Estimates

| Platform | Monthly Cost | What You Get |
|----------|--------------|--------------|
| Railway | $15-25 | 2 services, PostgreSQL, Redis |
| Render | $20-30 | Web service, PostgreSQL, Redis |
| AWS Lightsail | $13-20 | VPS, static IP, 40GB SSD |
| DigitalOcean | $12-24 | Droplet, managed database |
| Pakistan VPS | PKR 3000-5000 | VPS, local support |

---

## ✅ Pre-Launch Checklist

- [ ] Domain purchased and DNS configured
- [ ] SSL certificate installed (HTTPS)
- [ ] Environment variables configured
- [ ] SMTP credentials tested
- [ ] Safepay webhook configured
- [ ] Telegram bot configured (optional)
- [ ] Database migrations run
- [ ] Celery workers started
- [ ] Health check endpoint working
- [ ] Monitoring configured
- [ ] Firewall rules set up
- [ ] Backup strategy in place
- [ ] Error tracking (Sentry, etc.)

---

## 🆘 Support

If you encounter issues:

1. Check logs: `docker-compose logs -f`
2. Check health: `curl https://yourdomain.com/health`
3. Review this guide
4. Check GitHub issues: https://github.com/Khan-Feroz211/MyCyber-Project/issues

---

**Next Steps**: Deploy, test, and start selling! 🚀
