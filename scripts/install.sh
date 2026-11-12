#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run this installer as root on a clean Ubuntu Server 24.04 amd64 host." >&2
  exit 1
fi
. /etc/os-release
if [[ "${ID:-}" != "ubuntu" || "${VERSION_ID:-}" != "24.04" || "$(uname -m)" != "x86_64" ]]; then
  echo "Quiet Ops v1 requires Ubuntu Server 24.04 LTS on amd64." >&2
  exit 1
fi

if ! command -v node >/dev/null 2>&1; then
  echo "Node 26 is required before installing Quiet Ops." >&2
  exit 1
fi
node_major="$(node -p 'process.versions.node.split(".")[0]')"
if (( node_major < 26 )); then
  echo "Node 26 or newer is required before installing Quiet Ops." >&2
  exit 1
fi
if ! getent group quiet-ops >/dev/null 2>&1; then groupadd --system quiet-ops; fi
if ! getent group quiet-ops-control >/dev/null 2>&1; then groupadd --system quiet-ops-control; fi
if ! getent group quiet-ops-web >/dev/null 2>&1; then groupadd --system quiet-ops-web; fi
if ! id quiet-ops >/dev/null 2>&1; then
  useradd --system --gid quiet-ops --home-dir /var/lib/quiet-ops --create-home --shell /usr/sbin/nologin quiet-ops
fi
usermod --append --groups quiet-ops-control quiet-ops
if id www-data >/dev/null 2>&1; then
  # Web workers receive read-only ACLs on published releases; they must not
  # inherit the panel's writable control group.
  gpasswd --delete www-data quiet-ops >/dev/null 2>&1 || true
  usermod --append --groups quiet-ops-web www-data
  systemctl try-restart nginx || true
fi

install -d -m 0750 /opt/quiet-ops /var/log/quiet-ops /run/quiet-ops /etc/quiet-ops
install -d -m 0711 /var/lib/quiet-ops /var/lib/quiet-ops/sites
install -d -m 0750 /var/lib/quiet-ops/backups /var/lib/quiet-ops/generated
install -d -m 0750 /etc/nginx/conf.d /usr/local/lsws/conf/vhosts /etc/php/8.3/fpm/pool.d
setfacl -m u:www-data:--x,u:nobody:--x /run/quiet-ops 2>/dev/null || true
chown -R quiet-ops:quiet-ops /var/lib/quiet-ops /var/log/quiet-ops
chown root:quiet-ops-control /opt/quiet-ops
chown root:quiet-ops /run/quiet-ops
if [[ ! -e /etc/quiet-ops/panel.env ]]; then install -m 0640 -o root -g quiet-ops-control /dev/null /etc/quiet-ops/panel.env; fi
if [[ ! -e /etc/quiet-ops/agent.env ]]; then install -m 0640 -o root -g quiet-ops-control /dev/null /etc/quiet-ops/agent.env; fi
chown root:quiet-ops-control /etc/quiet-ops/panel.env /etc/quiet-ops/agent.env
install -m 0644 systemd/quiet-ops-panel.service /etc/systemd/system/quiet-ops-panel.service
install -m 0644 systemd/quiet-ops-agent.service /etc/systemd/system/quiet-ops-agent.service
install -m 0644 systemd/quiet-ops.tmpfiles /etc/tmpfiles.d/quiet-ops.conf
systemd-tmpfiles --create /etc/tmpfiles.d/quiet-ops.conf
systemctl daemon-reload
echo "Base directories and service units installed. Copy the signed release into /opt/quiet-ops, set PANEL_SECRET_KEY/PANEL_BACKUP_KEY in /etc/quiet-ops/panel.env, review agent.env, then enable the services. On first start the panel creates a self-signed certificate and opens at https://server-ip:8787; complete owner signup in the browser. PANEL_ADMIN_TOKEN is optional for unattended upgrades/tests."
