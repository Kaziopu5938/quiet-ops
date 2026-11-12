#!/usr/bin/env bash
set -euo pipefail

# Installs the light Ubuntu services used by the live adapters. It deliberately
# does not add an OpenLiteSpeed vendor repository or fetch a Node runtime: both
# require an operator-approved supply chain choice. Run install.sh after this.
if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root on Ubuntu Server 24.04 amd64." >&2
  exit 1
fi
. /etc/os-release
if [[ "${ID:-}" != "ubuntu" || "${VERSION_ID:-}" != "24.04" || "$(uname -m)" != "x86_64" ]]; then
  echo "Quiet Ops v1 requires Ubuntu Server 24.04 LTS on amd64." >&2
  exit 1
fi
if ! command -v node >/dev/null 2>&1 || (( "$(node -p 'process.versions.node.split(".")[0]')" < 26 )); then
  echo "Install Node.js 26 or newer from an operator-approved source before continuing." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  nginx php8.3-fpm php8.3-cli php8.3-mysql php8.3-curl php8.3-gd php8.3-mbstring php8.3-xml php8.3-zip \
  mariadb-server postgresql redis-server docker.io acl \
  git openssh-server cron certbot python3-certbot-nginx openssl

systemctl enable --now nginx php8.3-fpm ssh cron
# Keep the micro profile quiet: database daemons are installed but demand-started
# by the typed host agent only when a site provisions that engine.
systemctl disable --now mariadb postgresql redis-server || true
echo "Edge, PHP-FPM, SSH, and cron are ready. Database daemons are demand-started per site. Install OpenLiteSpeed from its reviewed vendor repository if OLS workloads are required, then run scripts/install.sh."
