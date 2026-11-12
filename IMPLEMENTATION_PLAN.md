# Quiet Ops implementation and operations plan

Quiet Ops is a single-node Ubuntu Server 24.04 LTS control plane for static, WordPress, Next.js, and Node.js sites. It deliberately has no mail stack and keeps the panel outside the public traffic path.

## Delivered phases

1. **Control plane and UI** — Node 26, SQLite WAL, React/Vite console, responsive indigo/teal/violet visual system, site inventory, jobs, backups, databases, monitoring, security, MCP, and settings.
2. **Workload lifecycle** — validated site templates, per-site identities, Nginx edge configuration, PHP-FPM pools for WordPress/Nginx, an OpenLiteSpeed/LSPHP configuration seam, Node/Next systemd units, cgroup limits, Docker-isolated runtimes/builds, immutable releases, deployment restart, rollback, and deletion cleanup. Git clones run as the site UID; Docker containers receive that UID/GID, a private network policy, bounded CPU/memory/PIDs, and no Docker socket.
3. **Recovery and data** — AES-256-GCM manual site bundles, owner-held recovery key, local or presigned HTTPS upload, clone/in-place restore, MariaDB/PostgreSQL dump replay, and namespace-scoped Redis serialized key restore.
4. **Security and access** — browser-only first-run signup (username, email, and password) with a one-time session token, self-signed HTTPS on first install, password/token login, bearer-token rotation, TOTP and one-time recovery codes, encrypted Git credentials, forced-command SFTP keys, path/argv allowlists, audit history, redacted logs, a separate control group for the privileged agent socket, and private token-authenticated MCP.
5. **Automation and operations** — typed cron jobs with site identity, five-minute timeout, `flock` overlap protection, SQLite metric samples, audit API, resource admission checks, and demand-started database daemons.

## Host rollout

On a clean Ubuntu Server 24.04 amd64 node with Node 26 installed:

```bash
sudo scripts/host-bootstrap.sh
sudo scripts/install.sh
npm run acceptance
# Install OpenLiteSpeed/LSPHP from the reviewed vendor source when OLS is needed:
npm run acceptance -- --full
```

Copy the signed panel release and `panel-agentd` into `/opt/quiet-ops`, then set `PANEL_SECRET_KEY` and `PANEL_BACKUP_KEY` in `/etc/quiet-ops/panel.env` (a high-entropy `PANEL_ADMIN_TOKEN` is optional for existing/unattended installs). Keep `PANEL_AGENT_LIVE=0` and `PANEL_LIVE` unset until the acceptance gate passes. Enable the services only after reviewing the generated unit files. OLS virtual-host/listener mapping and the LSPHP external-app name remain an operator-reviewed vendor integration; the panel refuses to treat an untested OLS binary as ready.

The panel defaults to `127.0.0.1:8787`. For MCP from a private VPN, set `PANEL_BIND` to a private interface, configure `PANEL_ALLOWED_ORIGIN`, and retain token authentication plus MFA. Do not expose the agent socket or a rootful container socket.

## Resource profile

The panel service is capped at 256 MiB and the host agent at 512 MiB/one CPU; the micro profile admits a 1 vCPU/1 GiB host for one small workload. Nginx, PHP-FPM, SSH, and cron start with the host; MariaDB, PostgreSQL, Redis, and Docker are installed, while database daemons start only when requested. Local Node/Next builds and many mixed sites require a larger node or remote/prebuilt artifacts.

## Verification

```bash
PANEL_BACKUP_KEY=test-recovery-key npm test
npm run check
npm run build
npm audit --omit=dev
cd agent && go test ./... && go build -o panel-agentd .
npm run acceptance -- --full
```

The first five checks are host-independent. The acceptance gate must be run on the target Ubuntu host; LMDE/development machines are expected to fail it.
