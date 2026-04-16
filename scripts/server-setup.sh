#!/bin/bash
set -euo pipefail

echo "=== MyCyber DLP Server Setup ==="

# 1. System update
apt-get update && apt-get upgrade -y

# 2. Install dependencies
apt-get install -y \
    curl wget git ufw fail2ban \
    apt-transport-https ca-certificates \
    gnupg lsb-release

# 3. Install Docker
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | gpg --dearmor -o /usr/share/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) \
    signed-by=/usr/share/keyrings/docker.gpg] \
    https://download.docker.com/linux/ubuntu \
    $(lsb_release -cs) stable" \
    | tee /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli \
    containerd.io docker-compose-plugin

# 4. Install k3s (lightweight K8s)
curl -sfL https://get.k3s.io | \
    INSTALL_K3S_EXEC="--disable traefik" sh -
mkdir -p ~/.kube
cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
chmod 600 ~/.kube/config

# 5. Install kubectl + helm
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# 6. Install cert-manager for SSL
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.15.3/cert-manager.yaml

# 7. Install nginx ingress controller
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.11.2/deploy/static/provider/cloud/deploy.yaml

# 8. Firewall setup
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

# 9. fail2ban for SSH protection
systemctl enable fail2ban
systemctl start fail2ban

# 10. Create deploy user
useradd -m -s /bin/bash deploy
usermod -aG docker deploy
mkdir -p /home/deploy/.kube
cp ~/.kube/config /home/deploy/.kube/config
chown -R deploy:deploy /home/deploy/.kube

echo "=== Server setup complete ==="
echo "k3s installed: $(k3s --version)"
echo "Next: run scripts/deploy.sh"
