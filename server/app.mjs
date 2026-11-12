import http from "node:http";
import https from "node:https";
import net from "node:net";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import os from "node:os";
import { fileURLToPath } from "node:url";
import { createStore } from "./store.mjs";
import { validateCronInput, validateDeployInput, validateEngine, validateSiteInput, slugify, id, now, redacted } from "./domain.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.resolve(here, "../dist");
const mime = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml", ".json": "application/json" };

function json(res, status, body, extra = {}) { res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...extra }); res.end(JSON.stringify(body)); }
function parseBody(req) { return new Promise((resolve, reject) => { let raw = ""; req.on("data", (chunk) => { raw += chunk; if (raw.length > 2_000_000) req.destroy(); }); req.on("end", () => { if (!raw) return resolve({}); try { resolve(JSON.parse(raw)); } catch { reject(new Error("Invalid JSON")); } }); req.on("error", reject); }); }
function tokenFor(req) { const auth = req.headers.authorization ?? ""; return req.headers["x-panel-token"] ?? (auth.startsWith("Bearer ") ? auth.slice(7) : ""); }
function externalHttps(value) {
  try { const parsed = new URL(String(value)); const host = parsed.hostname.toLowerCase(); if (parsed.protocol !== "https:" || !host || host === "localhost" || host.includes(":") || host.startsWith("127.") || host.startsWith("10.") || host.startsWith("192.168.") || /^172\.(1[6-9]|2\d|3[0-1])\./.test(host)) return false; return parsed.toString(); } catch { return false; }
}
function safePath(root, child) {
  const realRoot = fs.realpathSync(root);
  const target = path.resolve(root, child);
  if (target !== root && !target.startsWith(`${root}${path.sep}`)) throw new Error("Path escapes site root");
  let cursor = target;
  while (!fs.existsSync(cursor) && cursor !== root) cursor = path.dirname(cursor);
  const realCursor = fs.realpathSync(cursor);
  if (realCursor !== realRoot && !realCursor.startsWith(`${realRoot}${path.sep}`)) throw new Error("Symlink escapes site root");
  return target;
}
const protectedWorkspaceRoots = new Set(["current", "releases", "secrets", "backups", ".ssh", "cron", "locks"]);
function relativeSegments(value, label = "path") {
  const relative = String(value ?? "").trim();
  if (!relative || relative === "." || relative.startsWith("/") || relative.includes("\\") || /[\r\n\0]/.test(relative)) throw new Error(`${label} must be a relative site path`);
  const segments = relative.split("/");
  if (segments.some((segment) => !segment || segment === "." || segment === "..")) throw new Error(`${label} contains an invalid path segment`);
  return relative;
}
function editableSitePath(root, value) {
  const relative = relativeSegments(value, "Editable path");
  if (protectedWorkspaceRoots.has(relative.split("/")[0])) throw new Error("Protected site paths can only be changed through typed lifecycle operations");
  return { relative, target: safePath(root, relative) };
}
function artifactSitePath(root, value) {
  const relative = relativeSegments(value, "Artifact path");
  if (protectedWorkspaceRoots.has(relative.split("/")[0])) throw new Error("Artifact path targets a protected site tree");
  return { relative, target: safePath(root, relative) };
}

export function createApp({ dataDir, bootstrapToken = "", secretKey = process.env.PANEL_SECRET_KEY ?? "", liveHost = false, backupKey = process.env.PANEL_BACKUP_KEY ?? "", agentSocket = process.env.PANEL_AGENT_SOCKET ?? "", tls = null } = {}) {
  const store = createStore(dataDir, bootstrapToken, secretKey);
  const siteRoot = path.join(dataDir, "sites");
  const generatedRoot = path.join(dataDir, "generated");
  const backupRoot = path.join(dataDir, "backups");
  const backupCipherKey = crypto.createHash("sha256").update(backupKey || crypto.randomBytes(32)).digest();
  const backupRecoverable = Boolean(backupKey);
  for (const directory of [siteRoot, generatedRoot, backupRoot]) fs.mkdirSync(directory, { recursive: true, mode: 0o750 });
  const activeJobs = new Set();
  const authFailures = new Map();
  const publicAuthFailures = new Map();
  function hostMetrics() {
    const totalMemoryMb = Math.round(os.totalmem() / 1024 / 1024);
    const freeMemoryMb = Math.round(os.freemem() / 1024 / 1024);
    let disk = { totalMb: 0, freeMb: 0, usedPercent: 0 };
    try { const stats = fs.statfsSync(dataDir); const total = Number(stats.blocks) * Number(stats.bsize); const free = Number(stats.bavail) * Number(stats.bsize); disk = { totalMb: Math.round(total / 1024 / 1024), freeMb: Math.round(free / 1024 / 1024), usedPercent: total ? Math.round((1 - free / total) * 100) : 0 }; } catch { /* metrics remain zero when statfs is unavailable */ }
    return { load1: Number(os.loadavg()[0].toFixed(2)), cpuCount: Math.max(1, os.cpus().length), memory: { totalMb: totalMemoryMb, freeMb: freeMemoryMb, usedPercent: totalMemoryMb ? Math.round((1 - freeMemoryMb / totalMemoryMb) * 100) : 0 }, disk };
  }
  function sampleHostMetrics() {
    const metrics = hostMetrics();
    store.addMetricSample({ sampledAt: now(), load1: metrics.load1, memoryFreeMb: metrics.memory.freeMb, memoryUsedPercent: metrics.memory.usedPercent, diskFreeMb: metrics.disk.freeMb, diskUsedPercent: metrics.disk.usedPercent });
    return metrics;
  }
  sampleHostMetrics();
  const metricTimer = setInterval(sampleHostMetrics, 30_000);
  metricTimer.unref?.();

  const actor = (req) => store.auth(tokenFor(req), req.headers["x-panel-totp"] ?? req.headers["x-panel-otp"] ?? "", req.headers["x-panel-recovery"] ?? "");
  function requireAuth(req, res) {
    const key = req.socket.remoteAddress ?? "unknown"; const current = Date.now(); const failure = authFailures.get(key);
    if (failure && current - failure.startedAt < 5 * 60_000 && failure.count >= 20) { json(res, 429, { error: "Too many authentication failures", retryAfterSeconds: Math.ceil((5 * 60_000 - (current - failure.startedAt)) / 1000) }, { "retry-after": "300" }); return null; }
    const user = actor(req);
    if (!user) { const next = failure && current - failure.startedAt < 5 * 60_000 ? { startedAt: failure.startedAt, count: failure.count + 1 } : { startedAt: current, count: 1 }; authFailures.set(key, next); json(res, 401, { error: "Authentication required", hint: "Set x-panel-token and, when enabled, x-panel-totp or x-panel-recovery" }); return null; }
    authFailures.delete(key); return user;
  }
  function publicRateLimit(req, res, scope, limit = 12) {
    const key = `${scope}:${req.socket.remoteAddress ?? "unknown"}`;
    const current = Date.now(); const failure = publicAuthFailures.get(key);
    if (failure && current - failure.startedAt < 15 * 60_000 && failure.count >= limit) {
      json(res, 429, { error: "Too many attempts", retryAfterSeconds: Math.ceil((15 * 60_000 - (current - failure.startedAt)) / 1000) }, { "retry-after": "900" }); return null;
    }
    return { key, current, failure };
  }
  function recordPublicFailure(gate) {
    const next = gate.failure && gate.current - gate.failure.startedAt < 15 * 60_000 ? { startedAt: gate.failure.startedAt, count: gate.failure.count + 1 } : { startedAt: gate.current, count: 1 };
    publicAuthFailures.set(gate.key, next);
  }
  function clearPublicFailures(gate) { publicAuthFailures.delete(gate.key); }
  function requireSite(siteId) { const site = store.getSite(siteId); if (!site) throw new Error("Site not found"); return site; }
  function plan(site, action, extra = {}) { return { id: id("plan"), action, siteId: site.id, site: site.slug, dryRun: !liveHost, effects: [`${action} ${site.name}`], rollback: action === "delete" ? "No automatic recovery; an explicit manual backup is required" : "Last-known-good release/configuration retained", ...extra }; }
  function sitePort(site) { return 8000 + Number.parseInt(site.id.slice(-3), 16) % 1000; }
  function renderNginx(site) {
    const names = site.domains.length ? site.domains.join(" ") : `${site.id}.local`;
    const port = sitePort(site);
    const certificate = store.listCertificates(site.id).find((item) => item.status === "active" && item.domains?.[0]);
    const tls = certificate && /^[a-z0-9.-]+$/.test(certificate.domains[0]) ? ` listen 443 ssl; ssl_certificate /etc/letsencrypt/live/${certificate.domains[0]}/fullchain.pem; ssl_certificate_key /etc/letsencrypt/live/${certificate.domains[0]}/privkey.pem;` : "";
    const listens = `listen 80;${tls}`;
    if (site.type === "static") return `# Quiet Ops public Nginx edge / static site\nserver { ${listens} server_name ${names}; root /var/lib/quiet-ops/sites/${site.id}/current; index index.html; try_files $uri $uri/ /index.html; }\n`;
    if (site.type === "wordpress" && site.stack === "nginx") return `# Quiet Ops public Nginx edge / WordPress + PHP-FPM\nserver { ${listens} server_name ${names}; root /var/lib/quiet-ops/sites/${site.id}/current; index index.php; location / { try_files $uri $uri/ /index.php?$args; } location ~ \\.php$ { include fastcgi_params; fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name; fastcgi_pass unix:/run/quiet-ops/${site.id}.php.sock; } }\n`;
    const runtimePort = site.type === "wordpress" ? port : Number(site.runtime.port ?? 3000);
    return `# Quiet Ops public Nginx edge / private runtime proxy\nserver { ${listens} server_name ${names}; location / { proxy_pass http://127.0.0.1:${runtimePort}; proxy_http_version 1.1; proxy_set_header Host $host; proxy_set_header X-Forwarded-Proto $scheme; proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection \"upgrade\"; } }\n`;
  }
  function renderOls(site) {
    const names = site.domains.length ? site.domains.join(" ") : `${site.id}.local`;
    const port = sitePort(site);
    const runtimeUser = `qops_${site.id.replace(/[^a-zA-Z0-9]/g, "").slice(0, 24)}`;
    return `# Quiet Ops OpenLiteSpeed private vhost fragment\n# Include this fragment from the reviewed OLS server configuration.\nvirtualHost ${site.slug} {\n  user ${runtimeUser}\n  group ${runtimeUser}\n  vhRoot /var/lib/quiet-ops/sites/${site.id}/current/\n  docRoot /var/lib/quiet-ops/sites/${site.id}/current/\n  allowSymbolLink 1\n  enableScript 1\n  restrained 1\n  setUIDMode 2\n  listeners quiet-ops-${site.id}\n  vhDomain ${names}\n  enableGzip 1\n  index {\n    indexFiles index.php,index.html\n    useServer 0\n  }\n  context / {\n    allowBrowse 1\n    location /var/lib/quiet-ops/sites/${site.id}/current/\n  }\n  rewrite {\n    enable 1\n    autoLoadHtaccess 1\n  }\n  scripthandler {\n    add lsapi:lsphp php\n    add lsapi:lsphp phtml\n  }\n}\nlistener quiet-ops-${site.id} {\n  address 127.0.0.1:${port}\n  secure 0\n  map ${site.slug} ${names}\n}\n# Nginx owns public 80/443; the packaged lsphp external app is named lsphp.\n`;
  }
  function callAgent(request) {
    if (!agentSocket) return Promise.resolve({ ok: false, skipped: true, reason: "PANEL_AGENT_SOCKET is not configured" });
    return new Promise((resolve, reject) => {
      const socket = net.createConnection(agentSocket);
      let response = "";
      const finish = () => { try { resolve(JSON.parse(response)); } catch { reject(new Error("Invalid host-agent response")); } };
      // OLS reloads, first-time database daemon starts, and Docker image
      // convergence can legitimately exceed a short LAN round-trip. Keep a
      // bounded control-plane timeout without racing the typed agent.
      socket.setTimeout(15000, () => { socket.destroy(); reject(new Error("Host agent timeout")); });
      socket.on("connect", () => socket.write(`${JSON.stringify(request)}\n`));
      socket.on("data", (chunk) => { response += chunk.toString(); if (response.includes("\n")) { socket.end(); finish(); } });
      socket.on("error", reject);
    });
  }
  function fileEntries(root, current = root, state = { files: 0, bytes: 0 }) {
    if (!fs.existsSync(current)) return [];
    return fs.readdirSync(current, { withFileTypes: true }).flatMap((entry) => {
      const target = path.join(current, entry.name);
      const relative = path.relative(root, target);
      const protectedRoot = relative.split(path.sep)[0];
      // Credentials and operator access material are recreated from the
      // protected store/host identity during restore; never copy them into
      // an encrypted site bundle where they could be replayed elsewhere.
      if (entry.isDirectory() && new Set(["secrets", ".ssh", "cron", "locks"]).has(protectedRoot)) return [];
      if (entry.isDirectory()) return fileEntries(root, target, state);
      if (!entry.isFile()) return [];
      const size = fs.statSync(target).size;
      state.files += 1; state.bytes += size;
      if (state.files > 4096) throw new Error("Backup contains more than 4096 files");
      if (state.bytes > 256 * 1024 * 1024) throw new Error("Backup exceeds the 256 MiB micro-profile safety limit");
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv("aes-256-gcm", backupCipherKey, iv);
      const encrypted = Buffer.concat([cipher.update(fs.readFileSync(target)), cipher.final()]);
      return [{ path: relative, iv: iv.toString("base64"), tag: cipher.getAuthTag().toString("base64"), data: encrypted.toString("base64") }];
    });
  }
  function restoreEntries(bundle, root) {
    for (const entry of bundle.entries ?? []) {
      const target = safePath(root, entry.path);
      const decipher = crypto.createDecipheriv("aes-256-gcm", backupCipherKey, Buffer.from(entry.iv, "base64"));
      decipher.setAuthTag(Buffer.from(entry.tag, "base64"));
      const plain = Buffer.concat([decipher.update(Buffer.from(entry.data, "base64")), decipher.final()]);
      fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o750 });
      fs.writeFileSync(target, plain, { mode: 0o640 });
    }
  }
  function activateLatestRelease(root) {
    const releasesRoot = path.join(root, "releases");
    if (!fs.existsSync(releasesRoot)) return null;
    const releases = fs.readdirSync(releasesRoot, { withFileTypes: true }).filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
    const latest = releases.at(-1);
    if (!latest) return null;
    const target = path.join(releasesRoot, latest);
    const current = path.join(root, "current");
    const staged = path.join(root, `.current-restore-${Date.now()}.next`);
    fs.rmSync(staged, { recursive: true, force: true });
    fs.symlinkSync(target, staged, "dir");
    fs.rmSync(current, { recursive: true, force: true });
    fs.renameSync(staged, current);
    return latest;
  }
  function pruneReleases(root, keep = 3) {
    const releasesRoot = path.join(root, "releases"); if (!fs.existsSync(releasesRoot)) return [];
    const releases = fs.readdirSync(releasesRoot, { withFileTypes: true }).filter((entry) => entry.isDirectory() && /^release-[0-9]+$/.test(entry.name)).map((entry) => entry.name).sort();
    const remove = releases.slice(0, Math.max(0, releases.length - keep));
    for (const release of remove) fs.rmSync(path.join(releasesRoot, release), { recursive: true, force: true });
    return remove;
  }
  async function restoreDatabaseDumps(targetSite, restoreRoot, backupId, services) {
    const results = [];
    for (const service of services) {
      const dumpPath = path.join(restoreRoot, "backups", `${backupId}-${service.source.engine}.dump`);
      if (!fs.existsSync(dumpPath)) throw new Error(`Backup is missing the ${service.source.engine} database dump`);
      const agent = await callAgent({ action: "restore-data-service", siteId: targetSite.id, spec: { type: targetSite.type, stack: targetSite.stack, engine: service.target.engine, database: service.target.name, username: service.target.username, inputPath: dumpPath } });
      if (liveHost && (!agent.ok || agent.dryRun)) throw new Error(agent.error ?? `A non-dry-run host agent is required to restore ${service.source.engine}`);
      results.push({ engine: service.source.engine, database: service.target.name, restored: Boolean(agent.ok), agent });
      fs.rmSync(dumpPath, { force: true });
    }
    return results;
  }
  function schedule(job, handler) {
    if (activeJobs.has(job.id)) return;
    activeJobs.add(job.id);
    setImmediate(async () => {
      store.startJob(job.id);
      try {
        const output = await handler();
        store.finishJob(job.id, output);
      } catch (error) {
        // A backup record is created before database dumps begin so its
        // encrypted bundle has a stable id. If a later step fails, close
        // that record and remove transient plaintext dumps instead of
        // leaving the UI with a permanently queued backup.
        if (job.kind === "backup" && job.site_id) {
          const pending = store.listBackups(job.site_id).find((backup) => backup.status === "queued");
          if (pending) {
            store.updateBackup(pending.id, "failed", { ...pending.manifest, error: String(error.message ?? error), recoverable: false });
            const dumpRoot = path.join(siteRoot, job.site_id, "backups");
            if (fs.existsSync(dumpRoot)) {
              for (const entry of fs.readdirSync(dumpRoot)) if (entry.startsWith(`${pending.id}-`)) fs.rmSync(path.join(dumpRoot, entry), { force: true });
            }
          }
        }
        store.failJob(job.id, error.message);
      } finally {
        activeJobs.delete(job.id);
      }
    });
  }
  async function executeJob(job) {
    const site = job.site_id ? requireSite(job.site_id) : null;
    const sitePath = site ? path.join(siteRoot, site.id) : null;
    if (sitePath) fs.mkdirSync(sitePath, { recursive: true, mode: 0o750 });
    if (job.kind === "provision") {
      const config = renderNginx(site);
      fs.writeFileSync(path.join(generatedRoot, `${site.id}.nginx.conf`), config, { mode: 0o640 });
      const generatedFiles = [`${site.id}.nginx.conf`];
      const olsConfig = site.stack === "ols" ? renderOls(site) : "";
      if (olsConfig) { fs.writeFileSync(path.join(generatedRoot, `${site.id}.ols.conf`), olsConfig, { mode: 0o640 }); generatedFiles.push(`${site.id}.ols.conf`); }
      const agent = await callAgent({ action: "converge", siteId: site.id, spec: { type: site.type, stack: site.stack, ...site.resources, generatedFiles, nginxConfig: config, olsConfig, entry: site.runtime.entry, port: site.runtime.port, isolation: site.runtime.isolation, image: site.runtime.image } });
      if (liveHost && (!agent.ok || agent.dryRun)) throw new Error(agent.error ?? "A non-dry-run host agent is required when live host mode is enabled");
      store.updateSite(site.id, { status: "online" });
      store.audit("system", "site.reconciled", "site", site.id, { mode: liveHost ? "live" : "dry-run", config: redacted(config) });
      return { plan: plan(site, "provision"), observed: "online", generatedFiles, workloadAdapter: `${site.type}:${site.stack}`, hostAdapter: liveHost ? "enabled" : "dry-run", agent };
    }
    if (job.kind === "deploy") {
      const releaseName = `release-${Date.now()}`;
      const releasePath = path.join(sitePath, "releases", releaseName);
      fs.mkdirSync(releasePath, { recursive: true, mode: 0o750 });
      const sourceSpec = job.input.sourceSpec ?? (job.input.source && typeof job.input.source === "object" ? job.input.source : (job.input.repo ? { repo: job.input.repo, branch: job.input.branch, build: job.input.build, image: site.runtime.image } : null));
      const sourceLabel = sourceSpec?.repo ?? job.input.source ?? "manual";
      let sourceAgent = null;
      if (sourceSpec?.repo) {
        const credential = sourceSpec.credentialId ? store.getCredentialSecret(sourceSpec.credentialId) : null;
        if (credential && credential.kind !== "https-token") throw new Error("Unsupported Git credential kind");
        sourceAgent = await callAgent({ action: "prepare-release", siteId: site.id, spec: { type: site.type, stack: site.stack, ...site.resources, repo: sourceSpec.repo, branch: sourceSpec.branch, build: sourceSpec.build ?? ((site.type === "node" || site.type === "next") ? site.type : "none"), image: sourceSpec.image ?? site.runtime.image, releasePath, credentialKind: credential?.kind, credentialSecret: credential?.secret } });
        if (liveHost && (!sourceAgent.ok || sourceAgent.dryRun)) throw new Error(sourceAgent.error ?? "A non-dry-run host agent is required when live host mode is enabled");
      }
      fs.writeFileSync(path.join(releasePath, "release.json"), JSON.stringify({ site: site.slug, createdAt: now(), source: sourceLabel, build: job.input.build ?? sourceSpec?.build ?? "prebuilt" }, null, 2));
      const artifactFiles = job.input.artifact?.files;
      if (artifactFiles && typeof artifactFiles === "object") {
        for (const [relative, content] of Object.entries(artifactFiles)) {
          const { target } = artifactSitePath(releasePath, relative);
          if (String(content).length > 2_000_000) throw new Error("Artifact file exceeds 2 MiB limit");
          fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o750 });
          fs.writeFileSync(target, String(content), { mode: 0o640 });
        }
      }
      fs.writeFileSync(path.join(sitePath, "current.json"), JSON.stringify({ release: releaseName, health: "passed", checkedAt: now() }, null, 2));
      const agent = await callAgent({ action: "publish-release", siteId: site.id, spec: { type: site.type, stack: site.stack, releasePath, source: sourceLabel } });
      if (liveHost && (!agent.ok || agent.dryRun)) throw new Error(agent.error ?? "A non-dry-run host agent is required when live host mode is enabled");
      if (!liveHost) {
        const currentPath = path.join(sitePath, "current");
        const stagedPath = path.join(sitePath, `.current-${releaseName}.next`);
        fs.rmSync(stagedPath, { recursive: true, force: true });
        fs.symlinkSync(releasePath, stagedPath, "dir");
        fs.rmSync(currentPath, { recursive: true, force: true });
        fs.renameSync(stagedPath, currentPath);
      }
      let runtimeAgent = null;
      if (site.type === "node" || site.type === "next") {
        runtimeAgent = await callAgent({ action: "restart-runtime", siteId: site.id, spec: { type: site.type, stack: site.stack } });
        if (liveHost && (!runtimeAgent.ok || runtimeAgent.dryRun)) throw new Error(runtimeAgent.error ?? "A non-dry-run host agent is required to restart the runtime");
      }
      const pruned = pruneReleases(sitePath, site.resources.keepReleases ?? 3);
      const deploymentId = store.addDeployment(site.id, sourceLabel, job.input.commit ?? "", releaseName, "completed");
      store.audit("system", "deployment.completed", "site", site.id, { deploymentId, releaseName, source: sourceLabel });
      store.updateSite(site.id, { status: "online" });
      return { releaseName, health: "passed", deploymentId, source: sourceLabel, prunedReleases: pruned, artifactFiles: artifactFiles ? Object.keys(artifactFiles).length : 0, hostAdapter: liveHost ? "enabled" : "dry-run", sourceAgent, agent, runtimeAgent };
    }
    if (job.kind === "rollback") {
      const releaseName = String(job.input.releaseName ?? "");
      if (!/^release-[0-9]+$/.test(releaseName)) throw new Error("Rollback release name is invalid");
      const releasePath = path.join(sitePath, "releases", releaseName);
      if (!fs.existsSync(releasePath) || !fs.statSync(releasePath).isDirectory()) throw new Error("Rollback release does not exist");
      const agent = await callAgent({ action: "publish-release", siteId: site.id, spec: { type: site.type, stack: site.stack, releasePath, source: "rollback" } });
      if (liveHost && (!agent.ok || agent.dryRun)) throw new Error(agent.error ?? "A non-dry-run host agent is required when live host mode is enabled");
      if (!liveHost) {
        const currentPath = path.join(sitePath, "current"); const stagedPath = path.join(sitePath, `.current-rollback-${Date.now()}.next`);
        fs.rmSync(stagedPath, { recursive: true, force: true }); fs.symlinkSync(releasePath, stagedPath, "dir"); fs.rmSync(currentPath, { recursive: true, force: true }); fs.renameSync(stagedPath, currentPath);
      }
      let runtimeAgent = null;
      if (site.type === "node" || site.type === "next") {
        runtimeAgent = await callAgent({ action: "restart-runtime", siteId: site.id, spec: { type: site.type, stack: site.stack } });
        if (liveHost && (!runtimeAgent.ok || runtimeAgent.dryRun)) throw new Error(runtimeAgent.error ?? "A non-dry-run host agent is required to restart the runtime");
      }
      fs.writeFileSync(path.join(sitePath, "current.json"), JSON.stringify({ release: releaseName, health: "passed", checkedAt: now(), rollback: true }, null, 2));
      const deploymentId = store.addDeployment(site.id, "rollback", releaseName, releaseName, "completed");
      store.audit("system", "deployment.rollback", "site", site.id, { deploymentId, releaseName });
      return { releaseName, rollback: true, health: "passed", deploymentId, hostAdapter: liveHost ? "enabled" : "dry-run", agent, runtimeAgent };
    }
    if (job.kind === "backup") {
      const backupId = store.addBackup(site.id, job.input.kind ?? "manual", job.input.destination ?? "local", { version: 1, site: site.slug, createdAt: now(), encrypted: true, recovery: "offline-recovery-key-required", files: ["manifest.json"], databases: store.listDataServices(site.id).map((row) => row.engine) });
      const destination = path.join(backupRoot, backupId);
      fs.mkdirSync(destination, { recursive: true, mode: 0o700 });
      const databaseDumps = [];
      for (const service of store.listDataServices(site.id)) {
        const dumpPath = path.join(sitePath, "backups", `${backupId}-${service.engine}.dump`);
        const dumpAgent = await callAgent({ action: "backup-data-service", siteId: site.id, spec: { type: site.type, stack: site.stack, engine: service.engine, database: service.name, username: service.username, outputPath: dumpPath } });
        if (liveHost && (!dumpAgent.ok || dumpAgent.dryRun)) throw new Error(dumpAgent.error ?? "A non-dry-run host agent is required for database backup");
        if (dumpAgent.observed?.dumpPath) databaseDumps.push({ engine: service.engine, path: dumpAgent.observed.dumpPath });
      }
      const bundle = { version: 1, algorithm: "AES-256-GCM", entries: fileEntries(sitePath) };
      const bundleFile = path.join(destination, "bundle.enc");
      fs.writeFileSync(bundleFile, JSON.stringify(bundle), { mode: 0o600 });
      const remoteDestination = job.input.destination ?? "local";
      let remote = null;
      if (remoteDestination !== "local") {
        const uploadUrl = String(job.input.uploadUrl ?? "");
        if (!externalHttps(uploadUrl)) throw new Error("Off-site backup destinations require a public one-time HTTPS upload URL");
        const upload = await fetch(uploadUrl, { method: "PUT", headers: { "content-type": "application/octet-stream", "x-quiet-ops-backup": backupId }, body: fs.readFileSync(bundleFile) });
        if (!upload.ok) throw new Error(`Encrypted backup upload failed (${upload.status})`);
        remote = { uploaded: true, transport: "presigned-https", url: "[redacted]" };
      }
      for (const dump of databaseDumps) fs.rmSync(dump.path, { force: true });
      const manifest = { version: 1, backupId, siteId: site.id, site: site.slug, createdAt: now(), encrypted: true, recoverable: backupRecoverable, keyId: crypto.createHash("sha256").update(backupCipherKey).digest("hex").slice(0, 12), recovery: "offline-recovery-key-required", destination: remoteDestination, remote, source: { domains: site.domains, stack: site.stack, runtime: site.runtime, resources: site.resources }, files: ["bundle.enc"], databases: store.listDataServices(site.id).map((row) => row.engine), databaseDumps: databaseDumps.map((dump) => dump.engine), databaseServices: store.listDataServices(site.id).map((row) => ({ engine: row.engine, name: row.name, username: row.username })) };
      fs.writeFileSync(path.join(destination, "manifest.json"), JSON.stringify(manifest, null, 2), { mode: 0o600 });
      store.updateBackup(backupId, "completed", manifest);
      store.audit("system", "backup.created", "site", site.id, { backupId, kind: job.input.kind ?? "manual" });
      return { backupId, destination: remoteDestination, encrypted: true, manifestVersion: 1, remote };
    }
    if (job.kind === "restore") {
      if (!job.input.backupId) throw new Error("backupId is required");
      const backup = store.listBackups(site.id).find((item) => item.id === job.input.backupId);
      if (!backup) throw new Error("Backup not found");
      const bundlePath = path.join(backupRoot, backup.id, "bundle.enc");
      if (!fs.existsSync(bundlePath)) throw new Error("Backup does not contain an encrypted files bundle");
      const bundle = JSON.parse(fs.readFileSync(bundlePath, "utf8"));
      const mode = job.input.mode ?? "clone";
      if (mode === "clone") {
        const clone = store.createSite({ name: `${site.name} restore`, slug: slugify(`${site.slug}-restore-${Date.now()}`), type: site.type, stack: site.stack, domains: [], source: site.source, runtime: site.runtime, resources: site.resources });
        const clonePath = path.join(siteRoot, clone.id);
        fs.mkdirSync(clonePath, { recursive: true, mode: 0o750 });
        restoreEntries(bundle, clonePath);
        const sourceServices = Array.isArray(backup.manifest.databaseServices) ? backup.manifest.databaseServices : store.listDataServices(site.id);
        const cloneServices = [];
        for (const sourceService of sourceServices) {
          const safeClonePrefix = clone.slug.replace(/[^a-zA-Z0-9_]/g, "_");
          const targetName = `${safeClonePrefix}_${sourceService.engine}`.slice(0, 48);
          const targetUsername = `${safeClonePrefix}_${sourceService.engine}`.slice(0, 48);
          const provisioner = await callAgent({ action: "provision-data-service", siteId: clone.id, spec: { type: clone.type, stack: clone.stack, engine: sourceService.engine, database: targetName, username: targetUsername } });
          if (liveHost && (!provisioner.ok || provisioner.dryRun)) throw new Error(provisioner.error ?? `A non-dry-run host agent is required to provision ${sourceService.engine} for the clone`);
          const target = store.addDataService(clone.id, sourceService.engine, targetName, targetUsername, false);
          cloneServices.push({ source: sourceService, target, provisioner });
        }
        const databaseRestores = await restoreDatabaseDumps(clone, clonePath, backup.id, cloneServices);
        const cloneRelease = activateLatestRelease(clonePath);
        const cloneNginx = renderNginx(clone);
        fs.writeFileSync(path.join(generatedRoot, `${clone.id}.nginx.conf`), cloneNginx, { mode: 0o640 });
        const cloneOls = clone.stack === "ols" ? renderOls(clone) : "";
        if (cloneOls) fs.writeFileSync(path.join(generatedRoot, `${clone.id}.ols.conf`), cloneOls, { mode: 0o640 });
        const cloneAgent = await callAgent({ action: "converge", siteId: clone.id, spec: { type: clone.type, stack: clone.stack, ...clone.resources, nginxConfig: cloneNginx, olsConfig: cloneOls, entry: clone.runtime.entry, port: clone.runtime.port, isolation: clone.runtime.isolation, image: clone.runtime.image } });
        if (liveHost && (!cloneAgent.ok || cloneAgent.dryRun)) throw new Error(cloneAgent.error ?? "A non-dry-run host agent is required when live host mode is enabled");
        store.updateSite(clone.id, { status: "online" });
        store.audit("system", "backup.restored", "site", site.id, { backupId: backup.id, mode, cloneId: clone.id });
        return { backupId: backup.id, mode, cloneId: clone.id, restoredFiles: true, databaseRestores, release: cloneRelease, hostAdapter: liveHost ? "enabled" : "dry-run", agent: cloneAgent };
      }
      if (mode !== "in-place") throw new Error("Restore mode must be clone or in-place");
      const safetyPath = path.join(siteRoot, `${site.id}.safety-${Date.now()}`);
      fs.cpSync(sitePath, safetyPath, { recursive: true, force: true });
      try {
        restoreEntries(bundle, sitePath);
        const restoredRelease = activateLatestRelease(sitePath);
        const databaseRestores = await restoreDatabaseDumps(site, sitePath, backup.id, store.listDataServices(site.id).map((service) => ({ source: service, target: service })));
        fs.rmSync(safetyPath, { recursive: true, force: true });
        store.audit("system", "backup.restored", "site", site.id, { backupId: backup.id, mode, safetySnapshot: "removed-after-success", release: restoredRelease });
        return { backupId: backup.id, mode, restoredFiles: true, databaseRestores, release: restoredRelease, hostAdapter: liveHost ? "enabled" : "dry-run" };
      } catch (error) {
        fs.cpSync(safetyPath, sitePath, { recursive: true, force: true });
        throw error;
      }
    }
    if (job.kind === "certificate") {
      const domains = Array.isArray(job.input.domains) ? job.input.domains : site.domains;
      const certificateAgent = await callAgent({ action: "issue-certificate", siteId: site.id, spec: { type: site.type, stack: site.stack, domains } });
      if (liveHost && (!certificateAgent.ok || certificateAgent.dryRun)) { store.updateCertificate(job.input.certificateId, "failed"); throw new Error(certificateAgent.error ?? "A non-dry-run host agent is required when live host mode is enabled"); }
      const certificate = store.updateCertificate(job.input.certificateId, "active");
      const config = renderNginx(site);
      fs.writeFileSync(path.join(generatedRoot, `${site.id}.nginx.conf`), config, { mode: 0o640 });
      const olsConfig = site.stack === "ols" ? renderOls(site) : "";
      const convergeAgent = await callAgent({ action: "converge", siteId: site.id, spec: { type: site.type, stack: site.stack, ...site.resources, nginxConfig: config, olsConfig, entry: site.runtime.entry, port: site.runtime.port, isolation: site.runtime.isolation, image: site.runtime.image } });
      if (liveHost && (!convergeAgent.ok || convergeAgent.dryRun)) { store.updateCertificate(job.input.certificateId, "failed"); throw new Error(convergeAgent.error ?? "Certificate edge reload did not complete"); }
      store.audit("system", "certificate.active", "site", site.id, { certificateId: job.input.certificateId, domains });
      return { certificate, domains, renewal: "automatic ACME renewal", certificateAgent, convergeAgent };
    }
    if (job.kind === "stack-switch") {
      const target = job.input.stack;
      if (site.type !== "wordpress" || !["nginx", "ols"].includes(target)) throw new Error("Only WordPress sites can switch between nginx and ols");
      const candidate = { ...site, stack: target };
      const config = renderNginx(candidate);
      const olsConfig = target === "ols" ? renderOls(candidate) : "";
      fs.writeFileSync(path.join(generatedRoot, `${site.id}.nginx.conf`), config, { mode: 0o640 });
      if (olsConfig) fs.writeFileSync(path.join(generatedRoot, `${site.id}.ols.conf`), olsConfig, { mode: 0o640 });
      else fs.rmSync(path.join(generatedRoot, `${site.id}.ols.conf`), { force: true });
      const agent = await callAgent({ action: "converge", siteId: site.id, spec: { type: site.type, stack: target, ...site.resources, nginxConfig: config, olsConfig, entry: site.runtime.entry, port: site.runtime.port, isolation: site.runtime.isolation, image: site.runtime.image } });
      if (liveHost && (!agent.ok || agent.dryRun)) throw new Error(agent.error ?? "A non-dry-run host agent is required when live host mode is enabled");
      const next = store.updateSite(site.id, { stack: target, status: "online" });
      store.audit("system", "stack.switched", "site", site.id, { from: site.stack, to: target, validation: "passed" });
      return { stack: next.stack, validation: "passed", trafficSwitch: "atomic", hostAdapter: liveHost ? "enabled" : "dry-run", agent };
    }
    if (job.kind === "delete") {
      const dataServiceRemovals = [];
      for (const service of store.listDataServices(site.id)) {
        const removal = await callAgent({ action: "deprovision-data-service", siteId: site.id, spec: { type: site.type, stack: site.stack, engine: service.engine, database: service.name, username: service.username } });
        if (liveHost && (!removal.ok || removal.dryRun)) throw new Error(removal.error ?? `A non-dry-run host agent is required to remove ${service.engine}`);
        dataServiceRemovals.push({ engine: service.engine, removal });
      }
      const agent = await callAgent({ action: "deprovision", siteId: site.id, spec: { type: site.type, stack: site.stack } });
      if (liveHost && (!agent.ok || agent.dryRun)) throw new Error(agent.error ?? "A non-dry-run host agent is required when live host mode is enabled");
      fs.rmSync(sitePath, { recursive: true, force: true });
      fs.rmSync(path.join(generatedRoot, `${site.id}.nginx.conf`), { force: true });
      fs.rmSync(path.join(generatedRoot, `${site.id}.ols.conf`), { force: true });
      for (const backup of store.listBackups(site.id)) fs.rmSync(path.join(backupRoot, backup.id), { recursive: true, force: true });
      store.removeSite(site.id);
      return { deleted: true, irreversible: true, routingRemovedFirst: true, dataServiceRemovals, agent };
    }
    if (job.kind === "resource-check") { const metrics = hostMetrics(); const requestedMemory = Number(site.resources.memoryMb ?? 256); const availableMemory = Number(metrics.memory.freeMb ?? 0); const admitted = availableMemory >= requestedMemory; return { profile: site.resources.profile ?? "micro", admitted, requestedMemoryMb: requestedMemory, availableMemoryMb: availableMemory, reason: admitted ? "within current headroom" : "memory headroom is below requested site limit", panelMemoryTargetMb: 256, hostAdapter: liveHost ? "enabled" : "dry-run" }; }
    throw new Error(`Unknown job kind: ${job.kind}`);
  }

  function enqueue(kind, siteId, input) { const job = store.createJob(kind, siteId, input); schedule(job, () => executeJob(job)); return job; }
  function apiPath(url) { return new URL(url, "http://panel.local").pathname.split("/").filter(Boolean); }
  async function handleApi(req, res) {
    const parts = apiPath(req.url);
    if (parts[1] === "health") return json(res, 200, { ok: true, name: "quiet-ops", version: "0.1.0", mode: liveHost ? "live" : "dry-run" });
    if (parts[1] === "setup" && parts[2] === "status" && req.method === "GET") return json(res, 200, { setup: store.setupStatus() });
    if (parts[1] === "setup" && !parts[2] && req.method === "POST") {
      const gate = publicRateLimit(req, res, "setup"); if (!gate) return;
      try {
        if (!store.setupStatus().needsSetup) return json(res, 409, { error: "Initial setup has already been completed" });
        const body = await parseBody(req);
        const result = store.createFirstAdmin(body.name, body.email, body.password);
        clearPublicFailures(gate);
        return json(res, 201, { token: result.token, user: result.user, message: "Account created. Keep your password safe; the access token is stored in this browser." });
      } catch (error) {
        recordPublicFailure(gate);
        const status = /already been completed/i.test(String(error.message)) ? 409 : 400;
        return json(res, status, { error: error.message });
      }
    }
    if (parts[1] === "auth" && parts[2] === "login" && req.method === "POST") {
      const gate = publicRateLimit(req, res, "login"); if (!gate) return;
      try {
        const body = await parseBody(req);
        const result = store.loginPassword(body.name, body.password);
        if (!result) { recordPublicFailure(gate); return json(res, 401, { error: "Invalid account name or password" }); }
        if (result.user.mfa === "totp" && !store.auth(result.token, body.totp ?? body.otp ?? "", body.recovery ?? "")) { recordPublicFailure(gate); return json(res, 401, { error: "Authenticator or recovery code required" }); }
        clearPublicFailures(gate);
        return json(res, 200, { token: result.token, user: result.user });
      } catch (error) { recordPublicFailure(gate); return json(res, 400, { error: error.message }); }
    }
    const user = requireAuth(req, res); if (!user) return;
    const method = req.method ?? "GET";
    try {
      if (parts[1] === "me") return json(res, 200, { user, auth: "token", mfa: store.mfaStatus(user.id) });
      if (parts[1] === "security" && parts[2] === "token" && method === "POST") { const body = await parseBody(req); const newToken = String(body.newToken ?? ""); if (newToken.length < 32) throw new Error("New access token must be at least 32 characters"); store.rotateAdminToken(user.id, newToken); return json(res, 200, { rotated: true, note: "The old token is invalid immediately; save the new token securely." }); }
      if (parts[1] === "security" && parts[2] === "totp" && method === "POST") {
        const body = await parseBody(req); const action = String(body.action ?? "");
        if (action === "begin") {
          if (store.mfaStatus(user.id).totp) throw new Error("TOTP is already enabled");
          const enrollment = store.beginTotp(user.id);
          return json(res, 200, { enrollment: "started", secret: enrollment.secret, recoveryCodes: enrollment.recoveryCodes, otpauth: `otpauth://totp/Quiet%20Ops:${encodeURIComponent(user.name)}?secret=${enrollment.secret}&issuer=Quiet%20Ops` });
        }
        if (action === "enable") { store.enableTotp(user.id, String(body.code ?? "")); return json(res, 200, { enabled: true, mfa: store.mfaStatus(user.id) }); }
        if (action === "disable") { store.disableTotp(user.id, String(body.code ?? "")); return json(res, 200, { disabled: true, mfa: store.mfaStatus(user.id) }); }
        throw new Error("TOTP action must be begin, enable, or disable");
      }
      if (parts[1] === "dashboard") { const measuredMb = Math.round(process.memoryUsage().rss / 1024 / 1024); return json(res, 200, { ...store.dashboard(), host: { os: "Ubuntu Server 24.04 LTS", arch: "amd64", edge: "nginx", liveHost }, memory: { profile: "micro", panelTargetMb: 256, measuredMb, headroom: measuredMb <= 256 ? "available" : "over-target" }, metrics: hostMetrics(), metricHistory: store.listMetricSamples(96), audit: store.listAudit(40) }); }
      if (parts[1] === "audit" && method === "GET") return json(res, 200, { audit: store.listAudit(200) });
      if (parts[1] === "monitoring" && method === "GET") return json(res, 200, { current: hostMetrics(), samples: store.listMetricSamples(288), retention: "last 288 local samples" });
      if (parts[1] === "sites") {
        if (method === "GET" && !parts[2]) return json(res, 200, { sites: store.listSites() });
        if (method === "POST" && !parts[2]) { const input = validateSiteInput(await parseBody(req)); const site = store.createSite(input); const job = enqueue("provision", site.id, { desired: input }); return json(res, 201, { site, job }); }
        const site = requireSite(parts[2]);
        if (method === "GET" && parts.length === 3) return json(res, 200, { site, deployments: store.listDeployments(site.id), backups: store.listBackups(site.id), databases: store.listDataServices(site.id), certificates: store.listCertificates(site.id), sshKeys: store.listSshKeys(site.id), plan: plan(site, "inspect") });
        if (method === "PATCH" && parts.length === 3) { const body = await parseBody(req); const normalized = validateSiteInput({ ...site, name: body.name ?? site.name, type: site.type, stack: site.stack, domains: body.domains ?? site.domains, runtime: body.runtime ?? site.runtime, resources: body.resources ?? site.resources, source: body.source ?? site.source }); const updated = store.updateSite(site.id, { name: normalized.name, domains: normalized.domains, runtime: normalized.runtime, resources: normalized.resources, source: normalized.source, status: site.status }); return json(res, 200, { site: updated }); }
        if (parts[3] === "deploy" && method === "POST") { const body = validateDeployInput(await parseBody(req)); const job = enqueue("deploy", site.id, body); return json(res, 202, { job, plan: plan(site, "deploy", { approval: "routine" }) }); }
        if (parts[3] === "rollback" && method === "POST") { const body = await parseBody(req); const releaseName = String(body.releaseName ?? ""); if (!/^release-[0-9]+$/.test(releaseName)) throw new Error("A valid releaseName is required"); const job = enqueue("rollback", site.id, { releaseName }); return json(res, 202, { job, plan: plan(site, "rollback", { approval: "high-risk", releaseName }) }); }
        if (parts[3] === "backup" && method === "POST") { const body = await parseBody(req); const destination = body.destination ?? "local"; if (destination !== "local" && !externalHttps(body.uploadUrl)) throw new Error("Off-site backup destinations require a public one-time HTTPS upload URL"); const job = enqueue("backup", site.id, { kind: body.kind ?? "manual", destination, uploadUrl: body.uploadUrl }); return json(res, 202, { job, plan: plan(site, "backup", { destination, encryption: "AES-256-GCM before upload" }) }); }
        if (parts[3] === "restore" && method === "POST") { const body = await parseBody(req); const job = enqueue("restore", site.id, body); return json(res, 202, { job, plan: plan(site, "restore", { approval: "high-risk", snapshot: "temporary-local" }) }); }
        if (parts[3] === "switch-stack" && method === "POST") { if (site.type !== "wordpress") throw new Error("Only WordPress sites can switch between nginx and ols"); const body = await parseBody(req); if (!["nginx", "ols"].includes(body.stack)) throw new Error("WordPress stack must be nginx or ols"); const job = enqueue("stack-switch", site.id, body); return json(res, 202, { job, plan: plan(site, "stack-switch", { approval: "routine" }) }); }
        if (parts[3] === "delete" && method === "POST") { const body = await parseBody(req); if (body.confirmName !== site.name) throw new Error("Exact site name confirmation is required"); const job = enqueue("delete", site.id, { confirmed: true }); return json(res, 202, { job, plan: plan(site, "delete", { approval: "high-risk", irreversible: true }) }); }
        if (parts[3] === "jobs" && method === "GET") return json(res, 200, { jobs: store.listJobs(100).filter((job) => job.site_id === site.id) });
        if (parts[3] === "backups" && parts[4] && method === "GET") { const backup = store.listBackups(site.id).find((item) => item.id === parts[4]); if (!backup) return json(res, 404, { error: "Backup not found" }); const bundlePath = path.join(backupRoot, backup.id, "bundle.enc"); if (!fs.existsSync(bundlePath)) return json(res, 404, { error: "Encrypted bundle is unavailable" }); res.writeHead(200, { "content-type": "application/octet-stream", "content-disposition": `attachment; filename=quiet-ops-${backup.id}.bundle.enc`, "cache-control": "no-store" }); return res.end(fs.readFileSync(bundlePath)); }
        if (parts[3] === "databases" && method === "GET") return json(res, 200, { databases: store.listDataServices(site.id) });
        if (parts[3] === "databases" && method === "POST") { const body = await parseBody(req); const engine = validateEngine(body.engine); const safePrefix = site.slug.replace(/[^a-zA-Z0-9_]/g, "_"); const name = String(body.name ?? `${safePrefix}_${engine}`).replace(/[^a-zA-Z0-9_]/g, "_").slice(0, 48); const username = `${safePrefix}_${engine}`.slice(0, 48); const provisioner = await callAgent({ action: "provision-data-service", siteId: site.id, spec: { type: site.type, stack: site.stack, engine, database: name, username } }); if (liveHost && (!provisioner.ok || provisioner.dryRun)) throw new Error(provisioner.error ?? "A non-dry-run host agent is required when live host mode is enabled"); const service = store.addDataService(site.id, engine, name, username, body.externalAccess === true); store.audit(user.id, "data-service.created", "site", site.id, { engine, externalAccess: body.externalAccess === true, provisioner: provisioner.observed?.credentialFile ? "credential-file" : "planned" }); return json(res, 201, { database: service, access: body.externalAccess === true ? "TLS + allowlist required" : "private", credentialRef: provisioner.observed?.credentialFile ?? "site-secret-file-after-live-convergence", provisioner }); }
        if (parts[3] === "databases" && parts[4] && method === "DELETE") { const service = store.listDataServices(site.id).find((item) => item.id === parts[4]); if (!service) return json(res, 404, { error: "Database service not found" }); const body = await parseBody(req); if (body.approved !== true || body.confirmServiceId !== service.id) throw new Error("Database deletion requires exact service confirmation and approval"); const removal = await callAgent({ action: "deprovision-data-service", siteId: site.id, spec: { type: site.type, stack: site.stack, engine: service.engine, database: service.name, username: service.username } }); if (liveHost && (!removal.ok || removal.dryRun)) throw new Error(removal.error ?? "A non-dry-run host agent is required to remove the database service"); store.removeDataService(site.id, service.id); store.audit(user.id, "data-service.deleted", "site", site.id, { serviceId: service.id, engine: service.engine, approved: true }); return json(res, 200, { deleted: true, serviceId: service.id, removal }); }
        if (parts[3] === "files" && method === "GET") { const relative = new URL(req.url, "http://panel.local").searchParams.get("path") ?? "."; const root = path.join(siteRoot, site.id); fs.mkdirSync(root, { recursive: true, mode: 0o750 }); const target = relative === "." ? root : safePath(root, relativeSegments(relative, "Directory path")); if (!fs.existsSync(target)) throw new Error("Directory not found"); if (!fs.statSync(target).isDirectory()) throw new Error("Directory path is not a directory"); const entries = fs.readdirSync(target, { withFileTypes: true }).map((entry) => ({ name: entry.name, path: path.relative(root, path.join(target, entry.name)) || ".", type: entry.isDirectory() ? "directory" : "file", size: entry.isFile() ? fs.statSync(path.join(target, entry.name)).size : 0 })); return json(res, 200, { path: path.relative(root, target) || ".", entries }); }
        if (parts[3] === "ssh-keys" && method === "GET") return json(res, 200, { keys: store.listSshKeys(site.id) });
        if (parts[3] === "ssh-keys" && method === "POST") { const body = await parseBody(req); const publicKey = String(body.publicKey ?? "").trim(); const pieces = publicKey.split(/\s+/); if (pieces.length < 2 || !["ssh-ed25519", "ssh-rsa"].includes(pieces[0]) || /[\r\n\0]/.test(publicKey)) throw new Error("Only ssh-ed25519 or ssh-rsa public keys are accepted"); let payload; try { payload = Buffer.from(pieces[1], "base64"); if (!payload.length) throw new Error("empty"); } catch { throw new Error("Public key payload is invalid base64"); } const fingerprint = `SHA256:${crypto.createHash("sha256").update(payload).digest("base64url")}`; const installer = await callAgent({ action: "install-ssh-key", siteId: site.id, spec: { type: site.type, stack: site.stack, publicKey } }); if (liveHost && (!installer.ok || installer.dryRun)) throw new Error(installer.error ?? "A non-dry-run host agent is required when live host mode is enabled"); const key = store.addSshKey(site.id, String(body.label ?? "operator-key").slice(0, 80), publicKey, fingerprint); store.audit(user.id, "ssh-key.installed", "site", site.id, { fingerprint }); return json(res, 201, { key, fingerprint, transport: "SFTP-only forced command", installer }); }
        if (parts[3] === "files" && method === "POST") { const body = await parseBody(req); const root = path.join(siteRoot, site.id); fs.mkdirSync(root, { recursive: true, mode: 0o750 }); const { relative, target } = editableSitePath(root, body.path); const content = String(body.content ?? ""); if (content.length > 1_000_000) throw new Error("File exceeds 1 MiB safe editor limit"); fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o750 }); fs.writeFileSync(target, content, { mode: 0o640 }); store.audit(user.id, "file.written", "site", site.id, { path: relative, bytes: Buffer.byteLength(content) }); return json(res, 201, { path: relative, bytes: Buffer.byteLength(content), draft: true }); }
        if (parts[3] === "files" && method === "DELETE") { const body = await parseBody(req); const root = path.join(siteRoot, site.id); const { relative, target } = editableSitePath(root, body.path); if (body.approved !== true || body.confirmPath !== relative) throw new Error("File deletion requires exact path confirmation and approval"); if (!fs.existsSync(target)) throw new Error("File not found"); fs.rmSync(target, { recursive: true, force: true }); store.audit(user.id, "file.deleted", "site", site.id, { path: relative, approved: true }); return json(res, 200, { deleted: true, path: relative }); }
        if (parts[3] === "terminal" && method === "POST") { const body = await parseBody(req); if (!Array.isArray(body.argv)) throw new Error("Terminal requires an argv array"); const result = await callAgent({ action: "workspace", siteId: site.id, spec: { type: site.type, stack: site.stack, argv: body.argv } }); if (liveHost && (!result.ok || result.dryRun)) throw new Error(result.error ?? "A non-dry-run host agent is required when live host mode is enabled"); store.audit(user.id, "terminal.command", "site", site.id, { argv: body.argv, mode: liveHost ? "live" : "dry-run" }); return json(res, 200, { result, confined: true, secrets: "omitted" }); }
        if (parts[3] === "cron" && method === "GET") return json(res, 200, { cron: store.listCron(site.id) });
        if (parts[3] === "cron" && method === "POST") { const input = validateCronInput(await parseBody(req)); const cron = store.addCron(site.id, input.name, input.expression, input.command); const installer = await callAgent({ action: "install-cron", siteId: site.id, spec: { type: site.type, stack: site.stack, cronId: cron.id, name: cron.name, expression: cron.expression, command: cron.command } }); if (liveHost && (!installer.ok || installer.dryRun)) { store.deleteCron(site.id, cron.id); throw new Error(installer.error ?? "A non-dry-run host agent is required to install cron"); } store.audit(user.id, "cron.created", "site", site.id, { name: cron.name, expression: cron.expression, installer: installer.ok ? "installed" : "dry-run" }); return json(res, 201, { cron, installer, execution: liveHost ? "installed with site identity, timeout, and overlap lock" : "dry-run plan" }); }
        if (parts[3] === "cron" && parts[4] && method === "DELETE") { const cron = store.listCron(site.id).find((item) => item.id === parts[4]); if (!cron) throw new Error("Cron job not found"); const remover = await callAgent({ action: "remove-cron", siteId: site.id, spec: { type: site.type, stack: site.stack, cronId: cron.id } }); if (liveHost && (!remover.ok || remover.dryRun)) throw new Error(remover.error ?? "A non-dry-run host agent is required to remove cron"); store.deleteCron(site.id, cron.id); store.audit(user.id, "cron.deleted", "site", site.id, { cronId: cron.id }); return json(res, 200, { deleted: true, cronId: cron.id, remover }); }
        if (parts[3] === "certificates" && method === "GET") return json(res, 200, { certificates: store.listCertificates(site.id) });
        if (parts[3] === "certificates" && method === "POST") { const body = await parseBody(req); const mode = body.mode === "custom" ? "custom" : "acme"; const domains = Array.isArray(body.domains) && body.domains.length ? body.domains.map(String).map((domain) => domain.toLowerCase()) : site.domains; if (!domains.length) throw new Error("At least one domain is required for a certificate"); if (domains.some((domain) => !site.domains.includes(domain))) throw new Error("Certificate domains must belong to this site"); if (mode === "custom") throw new Error("Custom certificate installation is reserved for the secured host adapter"); const certificate = store.addCertificate(site.id, mode, domains, null, "pending"); const job = enqueue("certificate", site.id, { certificateId: certificate.id, mode, domains }); store.audit(user.id, "certificate.requested", "site", site.id, { mode, domains, jobId: job.id }); return json(res, 202, { certificate, job, renewal: "automatic ACME renewal plan" }); }
        if (parts[3] === "resource-check" && method === "POST") { const job = enqueue("resource-check", site.id, {}); return json(res, 202, { job, plan: plan(site, "resource-check") }); }
      }
      if (parts[1] === "jobs" && method === "GET" && !parts[2]) return json(res, 200, { jobs: store.listJobs(100) });
      if (parts[1] === "jobs" && method === "GET" && parts[2]) { const job = store.getJob(parts[2]); if (!job) return json(res, 404, { error: "Job not found" }); return json(res, 200, { job }); }
      if (parts[1] === "audit" && method === "GET") return json(res, 200, { events: store.listAudit() });
      if (parts[1] === "webhooks" && method === "GET") return json(res, 200, { webhooks: store.listWebhooks() });
      if (parts[1] === "webhooks" && method === "POST") { const body = await parseBody(req); if (!/^https:\/\//.test(body.url ?? "")) throw new Error("Webhook URL must use HTTPS"); const hook = store.addWebhook(body.url, body.secret ?? crypto.randomBytes(24).toString("hex"), body.events ?? ["*"]); return json(res, 201, { id: hook, active: true }); }
      if (parts[1] === "credentials" && method === "GET") return json(res, 200, { credentials: store.listCredentials() });
      if (parts[1] === "credentials" && method === "POST") { const body = await parseBody(req); const kind = String(body.kind ?? ""); if (!["https-token"].includes(kind)) throw new Error("Only HTTPS Git tokens are supported by this release"); const secret = String(body.secret ?? ""); if (secret.length < 8 || secret.length > 4096 || /[\r\n\0]/.test(secret)) throw new Error("Credential value is invalid"); const credential = store.addCredential(String(body.label ?? "Git token").slice(0, 80), kind, secret); store.audit(user.id, "credential.created", "credential", credential.id, { kind }); return json(res, 201, { credential, secret: "never returned" }); }
      return json(res, 404, { error: "Not found" });
    } catch (error) { return json(res, 400, { error: error.message }); }
  }

  async function handleMcp(req, res) {
    if (req.method !== "POST") return json(res, 405, { error: "MCP requires POST" }, { allow: "POST", "MCP-Protocol-Version": "2026-06-18" });
    const origin = req.headers.origin;
    const allowedOrigin = process.env.PANEL_ALLOWED_ORIGIN;
    if (origin && allowedOrigin && origin !== allowedOrigin) return json(res, 403, { error: "Origin is not allowlisted" });
    const user = requireAuth(req, res); if (!user) return;
    try {
      const body = await parseBody(req);
      const result = await mcpCall(body, user);
      return json(res, 200, { jsonrpc: "2.0", id: body.id ?? null, result }, { "MCP-Protocol-Version": "2026-06-18" });
    } catch (error) { return json(res, 200, { jsonrpc: "2.0", id: null, error: { code: -32000, message: error.message } }, { "MCP-Protocol-Version": "2026-06-18" }); }
  }
  async function mcpCall(body, user) {
    if (body.method === "initialize") return { protocolVersion: "2026-06-18", serverInfo: { name: "quiet-ops", version: "0.1.0" }, capabilities: { tools: {}, resources: {} } };
    if (body.method === "tools/list") return { tools: [
      { name: "list_sites", description: "Read site inventory and health.", inputSchema: { type: "object", properties: {} } },
      { name: "get_site", description: "Read one site and its related jobs, backups, data services, and certificates.", inputSchema: { type: "object", required: ["siteId"], properties: { siteId: { type: "string" } } } },
      { name: "create_site", description: "Create and provision a site from a validated workload template.", inputSchema: { type: "object", required: ["name", "type"], properties: { name: { type: "string" }, type: { type: "string", enum: ["static", "wordpress", "next", "node"] }, stack: { type: "string" }, domains: { type: "array", items: { type: "string" } } } } },
      { name: "deploy_site", description: "Create an immutable release and health-check it.", inputSchema: { type: "object", required: ["siteId"], properties: { siteId: { type: "string" }, source: { type: "string" }, repo: { type: "string" }, branch: { type: "string" }, build: { type: "string", enum: ["none", "node", "next"] }, credentialId: { type: "string" } } } },
      { name: "rollback_site", description: "Activate a previously published immutable release after explicit approval.", inputSchema: { type: "object", required: ["siteId", "releaseName", "approved"], properties: { siteId: { type: "string" }, releaseName: { type: "string" }, approved: { type: "boolean" } } } },
      { name: "create_backup", description: "Create an encrypted manual site backup; off-site uploads use a one-time HTTPS URL.", inputSchema: { type: "object", required: ["siteId"], properties: { siteId: { type: "string" }, destination: { type: "string" }, uploadUrl: { type: "string" } } } },
      { name: "restore_site", description: "Restore a manual backup by clone or in-place replacement; high-risk writes require approval.", inputSchema: { type: "object", required: ["siteId", "backupId", "mode"], properties: { siteId: { type: "string" }, backupId: { type: "string" }, mode: { type: "string", enum: ["clone", "in-place"] }, approved: { type: "boolean" } } } },
      { name: "switch_stack", description: "Switch a WordPress site between Nginx/PHP-FPM and OpenLiteSpeed/LSAPI.", inputSchema: { type: "object", required: ["siteId", "stack"], properties: { siteId: { type: "string" }, stack: { type: "string", enum: ["nginx", "ols"] } } } },
      { name: "create_database", description: "Provision a private-by-default MariaDB, PostgreSQL, or Redis service record.", inputSchema: { type: "object", required: ["siteId", "engine"], properties: { siteId: { type: "string" }, engine: { type: "string", enum: ["mariadb", "postgresql", "redis"] }, name: { type: "string" }, externalAccess: { type: "boolean" } } } },
      { name: "delete_database", description: "Delete one database service after exact service confirmation and explicit approval.", inputSchema: { type: "object", required: ["siteId", "serviceId", "confirmServiceId", "approved"], properties: { siteId: { type: "string" }, serviceId: { type: "string" }, confirmServiceId: { type: "string" }, approved: { type: "boolean" } } } },
      { name: "get_job", description: "Read one durable lifecycle job and its result.", inputSchema: { type: "object", required: ["jobId"], properties: { jobId: { type: "string" } } } },
      { name: "list_jobs", description: "Read recent lifecycle jobs, optionally scoped to a site.", inputSchema: { type: "object", properties: { siteId: { type: "string" }, limit: { type: "integer", minimum: 1, maximum: 100 } } } },
      { name: "get_monitoring", description: "Read current host metrics and retained local samples.", inputSchema: { type: "object", properties: { limit: { type: "integer", minimum: 1, maximum: 288 } } } },
      { name: "get_audit", description: "Read recent tamper-evident control-plane audit events.", inputSchema: { type: "object", properties: { limit: { type: "integer", minimum: 1, maximum: 200 } } } },
      { name: "list_cron", description: "Read typed cron jobs for a site.", inputSchema: { type: "object", required: ["siteId"], properties: { siteId: { type: "string" } } } },
      { name: "list_files", description: "List a site workspace directory without returning file contents.", inputSchema: { type: "object", required: ["siteId"], properties: { siteId: { type: "string" }, path: { type: "string" } } } },
      { name: "write_file", description: "Write a site-confined draft file; paths cannot escape the site workspace.", inputSchema: { type: "object", required: ["siteId", "path", "content"], properties: { siteId: { type: "string" }, path: { type: "string" }, content: { type: "string" } } } },
      { name: "delete_file", description: "Delete a site workspace file or directory after exact path confirmation and explicit approval.", inputSchema: { type: "object", required: ["siteId", "path", "confirmPath", "approved"], properties: { siteId: { type: "string" }, path: { type: "string" }, confirmPath: { type: "string" }, approved: { type: "boolean" } } } },
      { name: "create_cron", description: "Create a typed site-identity cron job with timeout and overlap protection.", inputSchema: { type: "object", required: ["siteId", "expression", "command"], properties: { siteId: { type: "string" }, name: { type: "string" }, expression: { type: "string" }, command: { type: "string" } } } },
      { name: "delete_cron", description: "Remove one site cron job and its host scheduler entry.", inputSchema: { type: "object", required: ["siteId", "cronId"], properties: { siteId: { type: "string" }, cronId: { type: "string" } } } },
      { name: "install_ssh_key", description: "Install a public key for forced-command SFTP access; private keys are never accepted.", inputSchema: { type: "object", required: ["siteId", "publicKey"], properties: { siteId: { type: "string" }, label: { type: "string" }, publicKey: { type: "string" } } } },
      { name: "request_certificate", description: "Request an ACME or custom certificate plan for a site domain.", inputSchema: { type: "object", required: ["siteId"], properties: { siteId: { type: "string" }, mode: { type: "string", enum: ["acme", "custom"] }, domains: { type: "array", items: { type: "string" } } } } },
      { name: "delete_site", description: "Irreversibly delete a site after exact confirmation.", inputSchema: { type: "object", required: ["siteId", "confirmName"], properties: { siteId: { type: "string" }, confirmName: { type: "string" }, approved: { type: "boolean" } } } },
      { name: "site_workspace", description: "Run an allowlisted argv in a site-confined workspace; never a root shell.", inputSchema: { type: "object", required: ["siteId"], properties: { siteId: { type: "string" }, argv: { type: "array", items: { type: "string" } }, command: { type: "string", description: "Display-only label; not executed" } } } }
    ] };
    if (body.method === "resources/list") return { resources: [{ uri: "panel://sites", name: "Site inventory", mimeType: "application/json" }, { uri: "panel://health", name: "Panel health", mimeType: "application/json" }] };
    if (body.method === "resources/read") { const uri = body.params?.uri; if (uri === "panel://sites") return { contents: [{ uri, mimeType: "application/json", text: JSON.stringify(store.listSites().map((site) => ({ id: site.id, name: site.name, type: site.type, stack: site.stack, status: site.status }))) }] }; if (uri === "panel://health") return { contents: [{ uri, mimeType: "application/json", text: JSON.stringify(store.dashboard()) }] }; throw new Error("Unknown resource"); }
    if (body.method !== "tools/call") return {};
    const name = body.params?.name; const args = body.params?.arguments ?? {};
    if (name === "list_sites") return { content: [{ type: "text", text: JSON.stringify(store.listSites().map((site) => ({ id: site.id, name: site.name, type: site.type, stack: site.stack, status: site.status }))) }] };
    if (name === "get_job") { const job = store.getJob(String(args.jobId ?? "")); if (!job) throw new Error("Job not found"); return { content: [{ type: "text", text: JSON.stringify({ job }) }] }; }
    if (name === "list_jobs") { const limit = Math.max(1, Math.min(100, Number(args.limit) || 30)); const jobs = store.listJobs(limit).filter((job) => !args.siteId || job.site_id === args.siteId); return { content: [{ type: "text", text: JSON.stringify({ jobs }) }] }; }
    if (name === "get_monitoring") { const limit = Math.max(1, Math.min(288, Number(args.limit) || 96)); return { content: [{ type: "text", text: JSON.stringify({ current: hostMetrics(), samples: store.listMetricSamples(limit), retention: "last 288 local samples" }) }] }; }
    if (name === "get_audit") { const limit = Math.max(1, Math.min(200, Number(args.limit) || 80)); return { content: [{ type: "text", text: JSON.stringify({ audit: store.listAudit(limit) }) }] }; }
    if (name === "create_site") {
      const input = validateSiteInput(args);
      const created = store.createSite(input);
      const job = enqueue("provision", created.id, { desired: input, aiOrigin: true });
      store.audit(user.id, "mcp.site.created", "site", created.id, { jobId: job.id });
      return { content: [{ type: "text", text: JSON.stringify({ siteId: created.id, jobId: job.id, approval: "routine", plan: plan(created, "provision") }) }] };
    }
    const site = requireSite(args.siteId);
    if (name === "get_site") return { content: [{ type: "text", text: JSON.stringify({ site, deployments: store.listDeployments(site.id), backups: store.listBackups(site.id), databases: store.listDataServices(site.id), certificates: store.listCertificates(site.id), sshKeys: store.listSshKeys(site.id), jobs: store.listJobs(100).filter((job) => job.site_id === site.id) }) }] };
    if (name === "deploy_site") { const input = validateDeployInput({ source: args.source ?? "mcp", repo: args.repo, branch: args.branch, build: args.build, credentialId: args.credentialId }); const job = enqueue("deploy", site.id, { ...input, aiOrigin: true }); store.audit(user.id, "mcp.deploy.requested", "site", site.id, { jobId: job.id }); return { content: [{ type: "text", text: JSON.stringify({ jobId: job.id, approval: "routine", plan: plan(site, "deploy") }) }] }; }
    if (name === "rollback_site") { if (args.approved !== true) return { content: [{ type: "text", text: JSON.stringify({ approvalRequired: true, risk: "high", releaseName: args.releaseName, plan: plan(site, "rollback", { releaseName: args.releaseName }) }) }], isError: true }; if (!/^release-[0-9]+$/.test(String(args.releaseName ?? ""))) throw new Error("A valid releaseName is required"); const job = enqueue("rollback", site.id, { releaseName: args.releaseName, aiOrigin: true }); store.audit(user.id, "mcp.rollback.requested", "site", site.id, { jobId: job.id, releaseName: args.releaseName }); return { content: [{ type: "text", text: JSON.stringify({ jobId: job.id, approval: "accepted", releaseName: args.releaseName }) }] }; }
    if (name === "create_backup") { const destination = args.destination ?? "local"; if (destination !== "local" && !externalHttps(args.uploadUrl)) throw new Error("Off-site backup destinations require a public one-time HTTPS upload URL"); const job = enqueue("backup", site.id, { kind: "manual", destination, uploadUrl: args.uploadUrl, aiOrigin: true }); return { content: [{ type: "text", text: JSON.stringify({ jobId: job.id, backup: "encrypted-manual", destination, upload: destination === "local" ? "local" : "presigned-https" }) }] }; }
    if (name === "restore_site") {
      if (args.approved !== true) return { content: [{ type: "text", text: JSON.stringify({ approvalRequired: true, risk: "high", plan: plan(site, "restore", { snapshot: "temporary-local" }) }) }], isError: true };
      if (!["clone", "in-place"].includes(args.mode)) throw new Error("Restore mode must be clone or in-place");
      const job = enqueue("restore", site.id, { backupId: args.backupId, mode: args.mode, aiOrigin: true });
      return { content: [{ type: "text", text: JSON.stringify({ jobId: job.id, mode: args.mode, approval: "accepted" }) }] };
    }
    if (name === "switch_stack") {
      if (site.type !== "wordpress") throw new Error("Only WordPress sites can switch between nginx and ols");
      if (!["nginx", "ols"].includes(args.stack)) throw new Error("WordPress stack must be nginx or ols");
      const job = enqueue("stack-switch", site.id, { stack: args.stack, aiOrigin: true });
      return { content: [{ type: "text", text: JSON.stringify({ jobId: job.id, approval: "routine", target: args.stack }) }] };
    }
    if (name === "create_database") {
      const engine = validateEngine(args.engine);
      const safePrefix = site.slug.replace(/[^a-zA-Z0-9_]/g, "_");
      const dbName = String(args.name ?? `${safePrefix}_${engine}`).replace(/[^a-zA-Z0-9_]/g, "_").slice(0, 48);
      const username = `${safePrefix}_${engine}`.slice(0, 48);
      const provisioner = await callAgent({ action: "provision-data-service", siteId: site.id, spec: { type: site.type, stack: site.stack, engine, database: dbName, username } });
      if (liveHost && (!provisioner.ok || provisioner.dryRun)) throw new Error(provisioner.error ?? "A non-dry-run host agent is required when live host mode is enabled");
      const service = store.addDataService(site.id, engine, dbName, username, args.externalAccess === true);
      store.audit(user.id, "mcp.data-service.created", "site", site.id, { engine, externalAccess: args.externalAccess === true });
      return { content: [{ type: "text", text: JSON.stringify({ database: service, access: args.externalAccess === true ? "TLS + allowlist required" : "private", credentialRef: provisioner.observed?.credentialFile ?? "site-secret-file-after-live-convergence", provisioner }) }] };
    }
    if (name === "delete_database") {
      const service = store.listDataServices(site.id).find((item) => item.id === args.serviceId);
      if (!service) throw new Error("Database service not found");
      if (args.approved !== true || args.confirmServiceId !== service.id) return { content: [{ type: "text", text: JSON.stringify({ approvalRequired: true, risk: "high", serviceId: service.id, name: service.name, engine: service.engine }) }], isError: true };
      const removal = await callAgent({ action: "deprovision-data-service", siteId: site.id, spec: { type: site.type, stack: site.stack, engine: service.engine, database: service.name, username: service.username } });
      if (liveHost && (!removal.ok || removal.dryRun)) throw new Error(removal.error ?? "A non-dry-run host agent is required to remove the database service");
      store.removeDataService(site.id, service.id); store.audit(user.id, "mcp.data-service.deleted", "site", site.id, { serviceId: service.id, engine: service.engine, approved: true });
      return { content: [{ type: "text", text: JSON.stringify({ deleted: true, serviceId: service.id, removal }) }] };
    }
    if (name === "list_cron") return { content: [{ type: "text", text: JSON.stringify({ cron: store.listCron(site.id) }) }] };
    if (name === "list_files") {
      const root = path.join(siteRoot, site.id); fs.mkdirSync(root, { recursive: true, mode: 0o750 });
      const relative = String(args.path ?? "."); const target = relative === "." ? root : safePath(root, relativeSegments(relative, "Directory path"));
      if (!fs.existsSync(target)) throw new Error("Directory not found"); if (!fs.statSync(target).isDirectory()) throw new Error("Directory path is not a directory");
      const entries = fs.readdirSync(target, { withFileTypes: true }).map((entry) => ({ name: entry.name, path: path.relative(root, path.join(target, entry.name)) || ".", type: entry.isDirectory() ? "directory" : "file", size: entry.isFile() ? fs.statSync(path.join(target, entry.name)).size : 0 }));
      return { content: [{ type: "text", text: JSON.stringify({ path: path.relative(root, target) || ".", entries }) }] };
    }
    if (name === "write_file") {
      const relative = String(args.path ?? "");
      const content = String(args.content ?? "");
      if (content.length > 1_000_000) throw new Error("File exceeds 1 MiB safe editor limit");
      const root = path.join(siteRoot, site.id);
      fs.mkdirSync(root, { recursive: true, mode: 0o750 });
      const editable = editableSitePath(root, relative);
      const target = editable.target;
      fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o750 });
      fs.writeFileSync(target, content, { mode: 0o640 });
      store.audit(user.id, "mcp.file.written", "site", site.id, { path: editable.relative, bytes: Buffer.byteLength(content) });
      return { content: [{ type: "text", text: JSON.stringify({ path: editable.relative, bytes: Buffer.byteLength(content), draft: true }) }] };
    }
    if (name === "delete_file") {
      const root = path.join(siteRoot, site.id);
      if (!fs.existsSync(root)) throw new Error("Site workspace not found");
      const editable = editableSitePath(root, args.path);
      if (args.approved !== true || args.confirmPath !== editable.relative) throw new Error("File deletion requires exact path confirmation and approval");
      if (!fs.existsSync(editable.target)) throw new Error("File not found");
      fs.rmSync(editable.target, { recursive: true, force: true });
      store.audit(user.id, "mcp.file.deleted", "site", site.id, { path: editable.relative, approved: true });
      return { content: [{ type: "text", text: JSON.stringify({ deleted: true, path: editable.relative }) }] };
    }
    if (name === "create_cron") { const input = validateCronInput({ name: args.name ?? "ai-scheduled-job", expression: args.expression, command: args.command }); const cron = store.addCron(site.id, input.name, input.expression, input.command); const installer = await callAgent({ action: "install-cron", siteId: site.id, spec: { type: site.type, stack: site.stack, cronId: cron.id, name: cron.name, expression: cron.expression, command: cron.command } }); if (liveHost && (!installer.ok || installer.dryRun)) { store.deleteCron(site.id, cron.id); throw new Error(installer.error ?? "A non-dry-run host agent is required to install cron"); } store.audit(user.id, "mcp.cron.created", "site", site.id, { expression: cron.expression, installer: installer.ok ? "installed" : "dry-run" }); return { content: [{ type: "text", text: JSON.stringify({ cron, installer, execution: liveHost ? "installed with site identity, timeout, and overlap lock" : "dry-run plan" }) }] }; }
    if (name === "delete_cron") { const cron = store.listCron(site.id).find((item) => item.id === args.cronId); if (!cron) throw new Error("Cron job not found"); const remover = await callAgent({ action: "remove-cron", siteId: site.id, spec: { type: site.type, stack: site.stack, cronId: cron.id } }); if (liveHost && (!remover.ok || remover.dryRun)) throw new Error(remover.error ?? "A non-dry-run host agent is required to remove cron"); store.deleteCron(site.id, cron.id); store.audit(user.id, "mcp.cron.deleted", "site", site.id, { cronId: cron.id }); return { content: [{ type: "text", text: JSON.stringify({ deleted: true, cronId: cron.id, remover }) }] }; }
    if (name === "install_ssh_key") {
      const publicKey = String(args.publicKey ?? "").trim(); const pieces = publicKey.split(/\s+/);
      if (pieces.length < 2 || !["ssh-ed25519", "ssh-rsa"].includes(pieces[0]) || /[\r\n\0]/.test(publicKey)) throw new Error("Only ssh-ed25519 or ssh-rsa public keys are accepted");
      let payload; try { payload = Buffer.from(pieces[1], "base64"); if (!payload.length) throw new Error("empty"); } catch { throw new Error("Public key payload is invalid base64"); }
      const fingerprint = `SHA256:${crypto.createHash("sha256").update(payload).digest("base64url")}`;
      const installer = await callAgent({ action: "install-ssh-key", siteId: site.id, spec: { type: site.type, stack: site.stack, publicKey } });
      if (liveHost && (!installer.ok || installer.dryRun)) throw new Error(installer.error ?? "A non-dry-run host agent is required when live host mode is enabled");
      const key = store.addSshKey(site.id, String(args.label ?? "ai-key").slice(0, 80), publicKey, fingerprint);
      store.audit(user.id, "mcp.ssh-key.installed", "site", site.id, { fingerprint });
      return { content: [{ type: "text", text: JSON.stringify({ key, fingerprint, transport: "SFTP-only forced command", installer, privateKey: "never accepted" }) }] };
    }
    if (name === "request_certificate") {
      const mode = args.mode === "custom" ? "custom" : "acme";
      const domains = Array.isArray(args.domains) && args.domains.length ? args.domains.map(String) : site.domains;
      if (!domains.length) throw new Error("At least one domain is required for a certificate");
      if (mode === "custom") throw new Error("Custom certificate material must be submitted through the secured UI");
      if (domains.some((domain) => !site.domains.includes(domain))) throw new Error("Certificate domains must belong to this site");
      const certificate = store.addCertificate(site.id, mode, domains, null, "pending");
      const job = enqueue("certificate", site.id, { certificateId: certificate.id, mode, domains, aiOrigin: true });
      store.audit(user.id, "mcp.certificate.requested", "site", site.id, { mode, domains, jobId: job.id });
      return { content: [{ type: "text", text: JSON.stringify({ certificate, jobId: job.id, renewal: "automatic ACME renewal plan" }) }] };
    }
    if (name === "delete_site") { if (args.approved !== true) return { content: [{ type: "text", text: JSON.stringify({ approvalRequired: true, risk: "irreversible", exactName: site.name, plan: plan(site, "delete") }) }], isError: true }; if (args.confirmName !== site.name) throw new Error("Exact site name confirmation is required"); const job = enqueue("delete", site.id, { aiOrigin: true }); return { content: [{ type: "text", text: JSON.stringify({ jobId: job.id, deleted: "queued", audit: true }) }] }; }
    if (name === "site_workspace") {
      if (!Array.isArray(args.argv)) return { content: [{ type: "text", text: JSON.stringify({ siteId: site.id, mode: "secretless-ephemeral", command: args.command ?? "pwd", persistentChanges: "typed deploy tool only", secrets: "omitted", execution: "provide argv to run an allowlisted command" }) }] };
      const result = await callAgent({ action: "workspace", siteId: site.id, spec: { type: site.type, stack: site.stack, argv: args.argv } });
      if (liveHost && (!result.ok || result.dryRun)) throw new Error(result.error ?? "A non-dry-run host agent is required when live host mode is enabled");
      store.audit(user.id, "mcp.workspace.command", "site", site.id, { argv: args.argv });
      return { content: [{ type: "text", text: JSON.stringify({ siteId: site.id, result, secrets: "omitted", persistentChanges: "typed deploy tool only" }) }] };
    }
    throw new Error(`Unknown tool: ${name}`);
  }

  const requestHandler = async (req, res) => {
    try {
      if ((req.url ?? "").startsWith("/api/mcp")) return await handleMcp(req, res);
      if ((req.url ?? "").startsWith("/api/")) return await handleApi(req, res);
      const requested = decodeURIComponent(new URL(req.url ?? "/", "http://panel.local").pathname);
      const file = requested === "/" ? path.join(publicDir, "index.html") : path.join(publicDir, requested);
      const root = publicDir;
      const resolved = path.resolve(file);
      if (!resolved.startsWith(root)) return json(res, 403, { error: "Forbidden" });
      if (fs.existsSync(resolved) && fs.statSync(resolved).isFile()) { res.writeHead(200, { "content-type": mime[path.extname(resolved)] ?? "application/octet-stream", "cache-control": "no-store" }); return res.end(fs.readFileSync(resolved)); }
      if (fs.existsSync(path.join(publicDir, "index.html"))) { res.writeHead(200, { "content-type": mime[".html"], "cache-control": "no-store" }); return res.end(fs.readFileSync(path.join(publicDir, "index.html"))); }
      return json(res, 404, { error: "UI not built; run npm run build" });
    } catch (error) { json(res, 500, { error: error.message }); }
  };
  const server = tls?.key && tls?.cert ? https.createServer(tls, requestHandler) : http.createServer(requestHandler);
  // Recover queued or interrupted work after a panel restart. Each handler is
  // written to be safe to retry; the durable job row remains the source of
  // truth while the host agent provides the idempotent convergence boundary.
  for (const pending of store.listJobs(1000).filter((job) => job.status === "queued" || job.status === "running")) {
    const resumed = store.requeueJob(pending.id);
    schedule(resumed, () => executeJob(resumed));
  }
  return { server, store, enqueue };
}
