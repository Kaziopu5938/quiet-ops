import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { createApp } from "../server/app.mjs";

async function startFixture(options = {}) {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "quiet-ops-test-"));
  const app = createApp({ dataDir, bootstrapToken: "test-token", backupKey: "test-recovery-key", ...options });
  await new Promise((resolve) => app.server.listen(0, "127.0.0.1", resolve));
  const address = app.server.address();
  const base = `http://127.0.0.1:${address.port}`;
  async function call(route, options = {}) {
    const response = await fetch(base + route, { ...options, headers: { "content-type": "application/json", "x-panel-token": "test-token", ...(options.headers ?? {}) } });
    return { status: response.status, body: await response.json() };
  }
  return { app, dataDir, call };
}

function totp(secret) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0; let value = 0; const bytes = [];
  for (const character of secret) { value = (value << 5) | alphabet.indexOf(character); bits += 5; if (bits >= 8) { bytes.push((value >>> (bits - 8)) & 255); bits -= 8; } }
  const key = Buffer.from(bytes); const counter = Math.floor(Date.now() / 1000 / 30); const message = Buffer.alloc(8); message.writeBigInt64BE(BigInt(counter));
  const digest = crypto.createHmac("sha1", key).update(message).digest(); const offset = digest[digest.length - 1] & 15; const number = ((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3];
  return String(number % 1_000_000).padStart(6, "0");
}

test("site lifecycle, jobs, safe files, database provisioning, and MCP work together", async (t) => {
  const fixture = await startFixture();
  t.after(() => { fixture.app.server.close(); fs.rmSync(fixture.dataDir, { recursive: true, force: true }); });
  const created = await fixture.call("/api/sites", { method: "POST", body: JSON.stringify({ name: "API Docs", type: "wordpress", stack: "nginx", domains: ["api.example.com"] }) });
  assert.equal(created.status, 201);
  const dashboard = await fixture.call("/api/dashboard");
  assert.equal(typeof dashboard.body.metrics.load1, "number");
  assert.ok(Array.isArray(dashboard.body.metricHistory));
  const monitoring = await fixture.call("/api/monitoring");
  assert.equal(monitoring.status, 200);
  assert.ok(Array.isArray(monitoring.body.samples));
  const audit = await fixture.call("/api/audit");
  assert.equal(audit.status, 200);
  assert.ok(Array.isArray(audit.body.audit));
  const siteId = created.body.site.id;
  await new Promise((resolve) => setTimeout(resolve, 25));
  const database = await fixture.call(`/api/sites/${siteId}/databases`, { method: "POST", body: JSON.stringify({ engine: "mariadb" }) });
  assert.equal(database.status, 201);
  const databaseId = database.body.database.id;
  const databaseDeleteMissingApproval = await fixture.call(`/api/sites/${siteId}/databases/${databaseId}`, { method: "DELETE", body: JSON.stringify({ confirmServiceId: databaseId }) });
  assert.equal(databaseDeleteMissingApproval.status, 400);
  const databaseDeleted = await fixture.call(`/api/sites/${siteId}/databases/${databaseId}`, { method: "DELETE", body: JSON.stringify({ approved: true, confirmServiceId: databaseId }) });
  assert.equal(databaseDeleted.status, 200);
  const databaseAfterDelete = await fixture.call(`/api/sites/${siteId}/databases`);
  assert.equal(databaseAfterDelete.body.databases.length, 0);
  const certificateRequest = await fixture.call(`/api/sites/${siteId}/certificates`, { method: "POST", body: JSON.stringify({ mode: "acme" }) });
  assert.equal(certificateRequest.status, 202);
  await new Promise((resolve) => setTimeout(resolve, 30));
  const certificateDetails = await fixture.call(`/api/sites/${siteId}`);
  assert.equal(certificateDetails.body.certificates[0].status, "active");
  assert.match(fs.readFileSync(path.join(fixture.dataDir, "generated", `${siteId}.nginx.conf`), "utf8"), /listen 443 ssl/);
  const deployment = await fixture.call(`/api/sites/${siteId}/deploy`, { method: "POST", body: JSON.stringify({ source: "archive", artifact: { files: { "index.html": "hello", "assets/app.js": "console.log('ok')" } } }) });
  assert.equal(deployment.status, 202);
  await new Promise((resolve) => setTimeout(resolve, 30));
  const deployed = await fixture.call(`/api/sites/${siteId}/jobs`);
  const deployJob = deployed.body.jobs.find((job) => job.kind === "deploy");
  assert.equal(deployJob.status, "completed");
  assert.equal(fs.readFileSync(path.join(fixture.dataDir, "sites", siteId, "current", "index.html"), "utf8"), "hello");
  const file = await fixture.call(`/api/sites/${siteId}/files`, { method: "POST", body: JSON.stringify({ path: "public/health.txt", content: "ok" }) });
  assert.equal(file.status, 201);
  const terminal = await fixture.call(`/api/sites/${siteId}/terminal`, { method: "POST", body: JSON.stringify({ argv: ["pwd"] }) });
  assert.equal(terminal.status, 200);
  assert.equal(terminal.body.confined, true);
  const sshKey = await fixture.call(`/api/sites/${siteId}/ssh-keys`, { method: "POST", body: JSON.stringify({ label: "test", publicKey: "ssh-ed25519 eA== operator" }) });
  assert.equal(sshKey.status, 201);
  assert.match(sshKey.body.fingerprint, /^SHA256:/);
  const credential = await fixture.call("/api/credentials", { method: "POST", body: JSON.stringify({ label: "GitHub read token", kind: "https-token", secret: "token-value-123" }) });
  assert.equal(credential.status, 201);
  assert.equal(credential.body.secret, "never returned");
  const gitDeployment = await fixture.call(`/api/sites/${siteId}/deploy`, { method: "POST", body: JSON.stringify({ sourceSpec: { repo: "https://git.example.com/team/site.git", branch: "main", build: "none", credentialId: credential.body.credential.id } }) });
  assert.equal(gitDeployment.status, 202);
  await new Promise((resolve) => setTimeout(resolve, 35));
  const secondDeployment = await fixture.call(`/api/sites/${siteId}/deploy`, { method: "POST", body: JSON.stringify({ source: "archive", artifact: { files: { "index.html": "second" } } }) });
  assert.equal(secondDeployment.status, 202);
  await new Promise((resolve) => setTimeout(resolve, 35));
  const firstRelease = deployJob.output.releaseName;
  const rollback = await fixture.call(`/api/sites/${siteId}/rollback`, { method: "POST", body: JSON.stringify({ releaseName: firstRelease }) });
  assert.equal(rollback.status, 202);
  await new Promise((resolve) => setTimeout(resolve, 35));
  assert.equal(fs.readFileSync(path.join(fixture.dataDir, "sites", siteId, "current", "index.html"), "utf8"), "hello");
  const backup = await fixture.call(`/api/sites/${siteId}/backup`, { method: "POST", body: JSON.stringify({ kind: "manual", destination: "local" }) });
  assert.equal(backup.status, 202);
  const unsafeRemote = await fixture.call(`/api/sites/${siteId}/backup`, { method: "POST", body: JSON.stringify({ kind: "manual", destination: "s3" }) });
  assert.equal(unsafeRemote.status, 400);
  await new Promise((resolve) => setTimeout(resolve, 35));
  const details = await fixture.call(`/api/sites/${siteId}`);
  const backupId = details.body.backups[0].id;
  assert.equal(details.body.backups[0].manifest.encrypted, true);
  assert.equal(details.body.backups[0].manifest.recoverable, true);
  const restore = await fixture.call(`/api/sites/${siteId}/restore`, { method: "POST", body: JSON.stringify({ backupId, mode: "clone" }) });
  assert.equal(restore.status, 202);
  await new Promise((resolve) => setTimeout(resolve, 35));
  const afterRestore = await fixture.call("/api/sites");
  assert.equal(afterRestore.body.sites.length, 2);
  const escaped = await fixture.call(`/api/sites/${siteId}/files`, { method: "POST", body: JSON.stringify({ path: "../../outside.txt", content: "no" }) });
  assert.equal(escaped.status, 400);
  const mcp = await fixture.call("/api/mcp", { method: "POST", body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }) });
  assert.equal(mcp.status, 200);
  assert.ok(mcp.body.result.tools.some((tool) => tool.name === "site_workspace"));
  assert.ok(mcp.body.result.tools.some((tool) => tool.name === "create_site"));
  assert.ok(mcp.body.result.tools.some((tool) => tool.name === "delete_file"));
  assert.ok(mcp.body.result.tools.some((tool) => tool.name === "get_monitoring"));
  const mcpMonitoring = await fixture.call("/api/mcp", { method: "POST", body: JSON.stringify({ jsonrpc: "2.0", id: 6, method: "tools/call", params: { name: "get_monitoring", arguments: { limit: 2 } } }) });
  assert.equal(mcpMonitoring.status, 200);
  assert.ok(Array.isArray(JSON.parse(mcpMonitoring.body.result.content[0].text).samples));
  const mcpCron = await fixture.call("/api/mcp", { method: "POST", body: JSON.stringify({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "create_cron", arguments: { siteId, expression: "*/15 * * * *", command: "wp cron event run --due-now" } } }) });
  assert.equal(mcpCron.status, 200);
  const mcpCronId = JSON.parse(mcpCron.body.result.content[0].text).cron.id;
  const mcpCronDelete = await fixture.call("/api/mcp", { method: "POST", body: JSON.stringify({ jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "delete_cron", arguments: { siteId, cronId: mcpCronId } } } ) });
  assert.equal(mcpCronDelete.status, 200);
  const mcpFile = await fixture.call("/api/mcp", { method: "POST", body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "write_file", arguments: { siteId, path: "mcp.txt", content: "typed" } } }) });
  assert.equal(mcpFile.status, 200);
  assert.equal(fs.readFileSync(path.join(fixture.dataDir, "sites", siteId, "mcp.txt"), "utf8"), "typed");
  const mcpFiles = await fixture.call("/api/mcp", { method: "POST", body: JSON.stringify({ jsonrpc: "2.0", id: 7, method: "tools/call", params: { name: "list_files", arguments: { siteId } } }) });
  assert.equal(mcpFiles.status, 200);
  assert.ok(JSON.parse(mcpFiles.body.result.content[0].text).entries.some((entry) => entry.name === "mcp.txt"));
  const mcpFileDelete = await fixture.call("/api/mcp", { method: "POST", body: JSON.stringify({ jsonrpc: "2.0", id: 8, method: "tools/call", params: { name: "delete_file", arguments: { siteId, path: "mcp.txt", confirmPath: "mcp.txt", approved: true } } }) });
  assert.equal(mcpFileDelete.status, 200);
  assert.equal(fs.existsSync(path.join(fixture.dataDir, "sites", siteId, "mcp.txt")), false);
  const mcpRestore = await fixture.call("/api/mcp", { method: "POST", body: JSON.stringify({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "restore_site", arguments: { siteId, backupId, mode: "in-place" } } }) });
  assert.equal(mcpRestore.body.result.isError, true);
  const rotated = await fixture.call("/api/security/token", { method: "POST", body: JSON.stringify({ newToken: "new-test-token-with-more-than-32-characters" }) });
  assert.equal(rotated.status, 200);
  const oldToken = await fixture.call("/api/me");
  assert.equal(oldToken.status, 401);
  const newToken = await fixture.call("/api/me", { headers: { "x-panel-token": "new-test-token-with-more-than-32-characters" } });
  assert.equal(newToken.status, 200);
  const enrollment = await fixture.call("/api/security/totp", { method: "POST", headers: { "x-panel-token": "new-test-token-with-more-than-32-characters" }, body: JSON.stringify({ action: "begin" }) });
  assert.equal(enrollment.status, 200);
  const enabled = await fixture.call("/api/security/totp", { method: "POST", headers: { "x-panel-token": "new-test-token-with-more-than-32-characters" }, body: JSON.stringify({ action: "enable", code: totp(enrollment.body.secret) }) });
  assert.equal(enabled.status, 200);
  const mfaMissing = await fixture.call("/api/me", { headers: { "x-panel-token": "new-test-token-with-more-than-32-characters" } });
  assert.equal(mfaMissing.status, 401);
  const mfaPresent = await fixture.call("/api/me", { headers: { "x-panel-token": "new-test-token-with-more-than-32-characters", "x-panel-totp": totp(enrollment.body.secret) } });
  assert.equal(mfaPresent.status, 200);
  const disabled = await fixture.call("/api/security/totp", { method: "POST", headers: { "x-panel-token": "new-test-token-with-more-than-32-characters", "x-panel-totp": totp(enrollment.body.secret) }, body: JSON.stringify({ action: "disable", code: totp(enrollment.body.secret) }) });
  assert.equal(disabled.status, 200);
});

test("workload adapters generate stack-specific plans and destructive actions require exact confirmation", async (t) => {
  const fixture = await startFixture();
  t.after(() => { fixture.app.server.close(); fs.rmSync(fixture.dataDir, { recursive: true, force: true }); });
  const created = await fixture.call("/api/sites", { method: "POST", body: JSON.stringify({ name: "Lite Site", type: "wordpress", stack: "ols", domains: ["lite.example.com"] }) });
  const siteId = created.body.site.id;
  await new Promise((resolve) => setTimeout(resolve, 30));
  const olsConfig = fs.readFileSync(path.join(fixture.dataDir, "generated", `${siteId}.ols.conf`), "utf8");
  assert.match(olsConfig, /virtualHost lite-site/);
  assert.match(olsConfig, /listener quiet-ops-/);
  assert.match(olsConfig, /lsapi:lsphp/);
  const cron = await fixture.call(`/api/sites/${siteId}/cron`, { method: "POST", body: JSON.stringify({ name: "wp-cron", expression: "*/5 * * * *", command: "wp cron event run --due-now" }) });
  assert.equal(cron.status, 201);
  assert.equal(cron.body.execution, "dry-run plan");
  const cronDelete = await fixture.call(`/api/sites/${siteId}/cron/${cron.body.cron.id}`, { method: "DELETE" });
  assert.equal(cronDelete.status, 200);
  const staticSite = await fixture.call("/api/sites", { method: "POST", body: JSON.stringify({ name: "Static Cannot Switch", type: "static" }) });
  const invalidSwitch = await fixture.call(`/api/sites/${staticSite.body.site.id}/switch-stack`, { method: "POST", body: JSON.stringify({ stack: "ols" }) });
  assert.equal(invalidSwitch.status, 400);
  const staticDelete = await fixture.call(`/api/sites/${staticSite.body.site.id}/delete`, { method: "POST", body: JSON.stringify({ confirmName: "Static Cannot Switch" }) });
  assert.equal(staticDelete.status, 202);
  await new Promise((resolve) => setTimeout(resolve, 30));
  const wrongDelete = await fixture.call(`/api/sites/${siteId}/delete`, { method: "POST", body: JSON.stringify({ confirmName: "wrong" }) });
  assert.equal(wrongDelete.status, 400);
  const deleted = await fixture.call(`/api/sites/${siteId}/delete`, { method: "POST", body: JSON.stringify({ confirmName: "Lite Site" }) });
  assert.equal(deleted.status, 202);
  await new Promise((resolve) => setTimeout(resolve, 30));
  const sites = await fixture.call("/api/sites");
  assert.equal(sites.body.sites.length, 0);
});

test("live mode refuses to mark a site online without a non-dry-run agent", async (t) => {
  const fixture = await startFixture({ liveHost: true, agentSocket: path.join(fixtureTempRoot(), "missing.sock") });
  t.after(() => { fixture.app.server.close(); fs.rmSync(fixture.dataDir, { recursive: true, force: true }); });
  const created = await fixture.call("/api/sites", { method: "POST", body: JSON.stringify({ name: "Guarded", type: "static" }) });
  assert.equal(created.status, 201);
  await new Promise((resolve) => setTimeout(resolve, 50));
  const jobs = await fixture.call(`/api/sites/${created.body.site.id}/jobs`);
  assert.equal(jobs.body.jobs[0].status, "failed");
});

test("queued work is resumed from SQLite after a control-plane restart", async (t) => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "quiet-ops-resume-"));
  const first = createApp({ dataDir, bootstrapToken: "test-token", backupKey: "test-recovery-key" });
  const site = first.store.createSite({ name: "Resume", slug: "resume", type: "static", stack: "nginx", domains: [], source: {}, runtime: {}, resources: { profile: "micro", memoryMb: 256, cpuPercent: 25, diskMb: 2048 } });
  const queued = first.store.createJob("resource-check", site.id, {});
  first.server.close();
  const second = createApp({ dataDir, bootstrapToken: "test-token", backupKey: "test-recovery-key" });
  t.after(() => { second.server.close(); fs.rmSync(dataDir, { recursive: true, force: true }); });
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.equal(second.store.getJob(queued.id).status, "completed");
});

function fixtureTempRoot() { return fs.mkdtempSync(path.join(os.tmpdir(), "quiet-ops-agent-")); }

test("first-run setup creates the owner in the browser and password login works", async (t) => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "quiet-ops-first-run-"));
  const app = createApp({ dataDir, backupKey: "test-recovery-key" });
  t.after(() => { app.server.close(); fs.rmSync(dataDir, { recursive: true, force: true }); });
  await new Promise((resolve) => app.server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${app.server.address().port}`;
  async function call(route, options = {}) { const response = await fetch(base + route, { ...options, headers: { "content-type": "application/json", ...(options.headers ?? {}) } }); return { status: response.status, body: await response.json() }; }
  assert.deepEqual((await call("/api/setup/status")).body.setup, { needsSetup: true, bootstrapOnly: false });
  const created = await call("/api/setup", { method: "POST", body: JSON.stringify({ name: "owner", email: "owner@example.com", password: "correct horse battery staple" }) });
  assert.equal(created.status, 201); assert.match(created.body.token, /^[A-Za-z0-9_-]{40,}$/); assert.equal(created.body.user.email, "owner@example.com");
  const dashboard = await call("/api/dashboard", { headers: { "x-panel-token": created.body.token } });
  assert.equal(dashboard.status, 200); assert.equal(typeof dashboard.body.metrics.memory.usedPercent, "number");
  const login = await call("/api/auth/login", { method: "POST", body: JSON.stringify({ name: "owner", password: "correct horse battery staple" }) });
  assert.equal(login.status, 200); assert.match(login.body.token, /^[A-Za-z0-9_-]{40,}$/);
  const duplicate = await call("/api/setup", { method: "POST", body: JSON.stringify({ name: "other", email: "other@example.com", password: "correct horse battery staple" }) });
  assert.equal(duplicate.status, 409);
});

test("an untouched token bootstrap is upgraded by browser signup", async (t) => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "quiet-ops-bootstrap-"));
  const app = createApp({ dataDir, bootstrapToken: "legacy-bootstrap-token", backupKey: "test-recovery-key" });
  t.after(() => { app.server.close(); fs.rmSync(dataDir, { recursive: true, force: true }); });
  await new Promise((resolve) => app.server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${app.server.address().port}`;
  async function call(route, options = {}) { const response = await fetch(base + route, { ...options, headers: { "content-type": "application/json", ...(options.headers ?? {}) } }); return { status: response.status, body: await response.json() }; }
  assert.equal((await call("/api/setup/status")).body.setup.needsSetup, true);
  const setup = await call("/api/setup", { method: "POST", body: JSON.stringify({ name: "owner", email: "owner@example.com", password: "correct horse battery staple" }) });
  assert.equal(setup.status, 201);
  assert.equal((await call("/api/dashboard", { headers: { "x-panel-token": "legacy-bootstrap-token" } })).status, 401);
  assert.equal((await call("/api/auth/login", { method: "POST", body: JSON.stringify({ name: "owner", password: "correct horse battery staple" }) })).status, 200);
});
