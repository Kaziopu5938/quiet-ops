import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { id, now, parseJson, redacted } from "./domain.mjs";

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32Encode(bytes) {
  let bits = 0; let value = 0; let output = "";
  for (const byte of bytes) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { output += BASE32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) output += BASE32[(value << (5 - bits)) & 31];
  return output;
}
function base32Decode(value) {
  const normalized = String(value ?? "").toUpperCase().replace(/=+$/g, "");
  let bits = 0; let current = 0; const output = [];
  for (const character of normalized) {
    const index = BASE32.indexOf(character);
    if (index < 0) throw new Error("Invalid TOTP secret");
    current = (current << 5) | index; bits += 5;
    if (bits >= 8) { output.push((current >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(output);
}
function totpCode(secret, timestamp = Date.now()) {
  const counter = Math.floor(timestamp / 1000 / 30);
  const message = Buffer.alloc(8); message.writeBigInt64BE(BigInt(counter));
  const digest = crypto.createHmac("sha1", base32Decode(secret)).update(message).digest();
  const offset = digest[digest.length - 1] & 15;
  const number = ((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3];
  return String(number % 1_000_000).padStart(6, "0");
}
function verifyTotp(secret, code) {
  if (!secret || !/^\d{6}$/.test(String(code ?? ""))) return false;
  const supplied = Buffer.from(String(code));
  for (const offset of [-30_000, 0, 30_000]) {
    const expected = Buffer.from(totpCode(secret, Date.now() + offset));
    if (crypto.timingSafeEqual(supplied, expected)) return true;
  }
  return false;
}
function encryptSecret(value, key) {
  const iv = crypto.randomBytes(12); const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return [iv, cipher.getAuthTag(), encrypted].map((part) => part.toString("base64url")).join(".");
}
function decryptSecret(value, key) {
  const [ivText, tagText, dataText] = String(value ?? "").split(".");
  if (!ivText || !tagText || !dataText) throw new Error("Invalid encrypted secret");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(ivText, "base64url"));
  decipher.setAuthTag(Buffer.from(tagText, "base64url"));
  return Buffer.concat([decipher.update(Buffer.from(dataText, "base64url")), decipher.final()]).toString("utf8");
}
function recoveryCode() {
  const raw = crypto.randomBytes(8).toString("hex").toUpperCase();
  return `${raw.slice(0, 4)}-${raw.slice(4, 8)}`;
}

const PASSWORD_COST = 131072;
const PASSWORD_BLOCK_SIZE = 8;
const PASSWORD_PARALLELISM = 1;
function hashPassword(value) {
  const password = String(value ?? "");
  if (!password) throw new Error("Password is required");
  const salt = crypto.randomBytes(16);
  const digest = crypto.scryptSync(password, salt, 32, { N: PASSWORD_COST, r: PASSWORD_BLOCK_SIZE, p: PASSWORD_PARALLELISM, maxmem: 256 * 1024 * 1024 });
  return `scrypt$${PASSWORD_COST}$${PASSWORD_BLOCK_SIZE}$${PASSWORD_PARALLELISM}$${salt.toString("base64url")}$${digest.toString("base64url")}`;
}
function verifyPassword(value, encoded) {
  try {
    const [scheme, nText, rText, pText, saltText, digestText] = String(encoded ?? "").split("$");
    if (scheme !== "scrypt" || !saltText || !digestText) return false;
    const expected = Buffer.from(digestText, "base64url");
    const actual = crypto.scryptSync(String(value ?? ""), Buffer.from(saltText, "base64url"), expected.length, { N: Number(nText), r: Number(rText), p: Number(pText), maxmem: 256 * 1024 * 1024 });
    return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
  } catch { return false; }
}

export function createStore(dataDir, bootstrapToken = "", secretKey = "") {
  fs.mkdirSync(dataDir, { recursive: true, mode: 0o750 });
  const db = new DatabaseSync(path.join(dataDir, "panel.sqlite"));
  db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;");
  db.exec(`
    CREATE TABLE IF NOT EXISTS admins (id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT, role TEXT NOT NULL, token_hash TEXT NOT NULL, password_hash TEXT, totp_secret TEXT, totp_enabled INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS recovery_codes (id TEXT PRIMARY KEY, admin_id TEXT NOT NULL, code_hash TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, used_at TEXT);
    CREATE TABLE IF NOT EXISTS sites (id TEXT PRIMARY KEY, name TEXT NOT NULL, slug TEXT UNIQUE NOT NULL, type TEXT NOT NULL, stack TEXT NOT NULL, status TEXT NOT NULL, domains_json TEXT NOT NULL, source_json TEXT NOT NULL, runtime_json TEXT NOT NULL, resources_json TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, kind TEXT NOT NULL, site_id TEXT, status TEXT NOT NULL, progress INTEGER NOT NULL, input_json TEXT NOT NULL, output_json TEXT, error TEXT, created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT);
    CREATE TABLE IF NOT EXISTS deployments (id TEXT PRIMARY KEY, site_id TEXT NOT NULL, source TEXT NOT NULL, commit_ref TEXT, release_name TEXT, status TEXT NOT NULL, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS backups (id TEXT PRIMARY KEY, site_id TEXT NOT NULL, kind TEXT NOT NULL, destination TEXT NOT NULL, status TEXT NOT NULL, manifest_json TEXT NOT NULL, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS data_services (id TEXT PRIMARY KEY, site_id TEXT NOT NULL, engine TEXT NOT NULL, name TEXT NOT NULL, username TEXT NOT NULL, external_access INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS cron_jobs (id TEXT PRIMARY KEY, site_id TEXT NOT NULL, name TEXT NOT NULL, expression TEXT NOT NULL, command TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS ssh_keys (id TEXT PRIMARY KEY, site_id TEXT NOT NULL, label TEXT NOT NULL, public_key TEXT NOT NULL, fingerprint TEXT NOT NULL, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS certificates (id TEXT PRIMARY KEY, site_id TEXT NOT NULL, mode TEXT NOT NULL, domains_json TEXT NOT NULL, status TEXT NOT NULL, expires_at TEXT, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS audit (id TEXT PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL, target_type TEXT, target_id TEXT, details_json TEXT NOT NULL, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS webhooks (id TEXT PRIMARY KEY, url TEXT NOT NULL, secret TEXT NOT NULL, events_json TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS credentials (id TEXT PRIMARY KEY, label TEXT NOT NULL, kind TEXT NOT NULL, secret_enc TEXT NOT NULL, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS metric_samples (id TEXT PRIMARY KEY, sampled_at TEXT NOT NULL, load1 REAL NOT NULL, memory_free_mb INTEGER NOT NULL, memory_used_percent REAL NOT NULL, disk_free_mb INTEGER NOT NULL, disk_used_percent REAL NOT NULL);
  `);
  for (const migration of [
    "ALTER TABLE admins ADD COLUMN email TEXT",
    "ALTER TABLE admins ADD COLUMN password_hash TEXT",
    "ALTER TABLE admins ADD COLUMN totp_secret TEXT",
    "ALTER TABLE admins ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0",
  ]) { try { db.exec(migration); } catch { /* column already exists */ } }
  const secretCipherKey = crypto.createHash("sha256").update(secretKey || bootstrapToken || crypto.randomBytes(32)).digest();
  const existing = db.prepare("SELECT id FROM admins LIMIT 1").get();
  if (!existing && bootstrapToken) db.prepare("INSERT INTO admins (id,name,role,token_hash,created_at) VALUES (?,?,?,?,?)").run("admin_owner", "Owner", "owner", hashToken(bootstrapToken), now());

  const rows = (sql, ...args) => db.prepare(sql).all(...args);
  const one = (sql, ...args) => db.prepare(sql).get(...args);
  const run = (sql, ...args) => db.prepare(sql).run(...args);
  const audit = (actor, action, targetType, targetId, details = {}) => run("INSERT INTO audit (id,actor,action,target_type,target_id,details_json,created_at) VALUES (?,?,?,?,?,?,?)", id("audit"), actor, action, targetType, targetId, JSON.stringify(redacted(details)), now());
  const consumeRecovery = (adminId, code) => {
    const row = one("SELECT id FROM recovery_codes WHERE admin_id=? AND code_hash=? AND used=0", adminId, hashToken(String(code ?? "").trim().toUpperCase()));
    if (!row) return false;
    run("UPDATE recovery_codes SET used=1,used_at=? WHERE id=?", now(), row.id);
    audit(adminId, "admin.recovery-code.used", "admin", adminId, {});
    return true;
  };
  const siteFromRow = (row) => row && ({ ...row, domains: parseJson(row.domains_json, []), source: parseJson(row.source_json, {}), runtime: parseJson(row.runtime_json, {}), resources: parseJson(row.resources_json, {}) });
  const jobFromRow = (row) => row && ({ ...row, input: parseJson(row.input_json, {}), output: parseJson(row.output_json ?? "{}", {}) });
  return {
    db,
    dataDir,
    setupStatus() {
      const count = Number(one("SELECT COUNT(*) AS count FROM admins").count ?? 0);
      const bootstrapOnly = count === 1 && Boolean(one("SELECT id FROM admins WHERE id='admin_owner' AND password_hash IS NULL AND totp_enabled=0")?.id);
      return { needsSetup: count === 0 || bootstrapOnly, bootstrapOnly };
    },
    createFirstAdmin(name, email, password) {
      const cleanName = String(name ?? "").trim(); const cleanEmail = String(email ?? "").trim().toLowerCase();
      if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{1,79}$/.test(cleanName)) throw new Error("Username must be 2–80 letters, numbers, dots, dashes, or underscores");
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail) || cleanEmail.length > 254) throw new Error("Enter a valid email address");
      if (String(password ?? "").length < 12) throw new Error("Password must be at least 12 characters");
      const current = Number(one("SELECT COUNT(*) AS count FROM admins").count ?? 0);
      const existingBootstrap = one("SELECT id FROM admins WHERE id='admin_owner' AND password_hash IS NULL AND totp_enabled=0");
      if (current !== 0 && !(current === 1 && existingBootstrap)) throw new Error("Initial setup has already been completed");
      const adminId = "admin_owner";
      const token = crypto.randomBytes(32).toString("base64url");
      const timestamp = now();
      db.exec("BEGIN IMMEDIATE");
      try {
        const insideCount = Number(one("SELECT COUNT(*) AS count FROM admins").count ?? 0);
        const insideBootstrap = one("SELECT id FROM admins WHERE id='admin_owner' AND password_hash IS NULL AND totp_enabled=0");
        if (insideCount === 0) run("INSERT INTO admins (id,name,email,role,token_hash,password_hash,created_at) VALUES (?,?,?,?,?,?,?)", adminId, cleanName, cleanEmail, "owner", hashToken(token), hashPassword(password), timestamp);
        else if (insideCount === 1 && insideBootstrap) run("UPDATE admins SET name=?,email=?,role='owner',token_hash=?,password_hash=? WHERE id=?", cleanName, cleanEmail, hashToken(token), hashPassword(password), adminId);
        else throw new Error("Initial setup has already been completed");
        db.exec("COMMIT");
      } catch (error) { db.exec("ROLLBACK"); throw error; }
      audit(adminId, "admin.initial-signup.completed", "admin", adminId, { name: cleanName, email: cleanEmail });
      return { token, user: { id: adminId, name: cleanName, email: cleanEmail, role: "owner", mfa: "not-configured" } };
    },
    loginPassword(name, password) {
      const cleanName = String(name ?? "").trim();
      const row = one("SELECT id,name,email,role,password_hash,totp_enabled FROM admins WHERE lower(name)=lower(?)", cleanName);
      if (!row || !row.password_hash || !verifyPassword(password, row.password_hash)) return null;
      const token = crypto.randomBytes(32).toString("base64url");
      run("UPDATE admins SET token_hash=? WHERE id=?", hashToken(token), row.id);
      audit(row.id, "admin.password-login", "admin", row.id, {});
      return { token, user: { id: row.id, name: row.name, email: row.email, role: row.role, mfa: Number(row.totp_enabled) === 1 ? "totp" : "not-configured" } };
    },
    auth(token, otp = "", recovery = "") {
      const row = one("SELECT id,name,role,totp_secret,totp_enabled FROM admins WHERE token_hash = ?", hashToken(token ?? ""));
      if (!row) return null;
      if (Number(row.totp_enabled) === 1) {
        let secret = ""; try { secret = decryptSecret(row.totp_secret, secretCipherKey); } catch { return null; }
        if (!verifyTotp(secret, otp) && !consumeRecovery(row.id, recovery)) return null;
      }
      return { id: row.id, name: row.name, role: row.role, mfa: Number(row.totp_enabled) === 1 ? "totp" : "not-configured" };
    },
    mfaStatus(adminId) { const row = one("SELECT totp_enabled FROM admins WHERE id=?", adminId); const remaining = one("SELECT COUNT(*) AS count FROM recovery_codes WHERE admin_id=? AND used=0", adminId)?.count ?? 0; return { totp: Boolean(row && Number(row.totp_enabled) === 1), passkey: false, recoveryCodes: Number(remaining) > 0, recoveryCodesRemaining: Number(remaining) }; },
    beginTotp(adminId) {
      const secret = base32Encode(crypto.randomBytes(20));
      const codes = Array.from({ length: 8 }, recoveryCode);
      run("UPDATE admins SET totp_secret=?,totp_enabled=0 WHERE id=?", encryptSecret(secret, secretCipherKey), adminId);
      run("DELETE FROM recovery_codes WHERE admin_id=?", adminId);
      for (const code of codes) run("INSERT INTO recovery_codes (id,admin_id,code_hash,created_at) VALUES (?,?,?,?)", id("recovery"), adminId, hashToken(code), now());
      audit(adminId, "admin.totp.enrollment.started", "admin", adminId, {});
      return { secret, recoveryCodes: codes };
    },
    enableTotp(adminId, code) {
      const row = one("SELECT totp_secret FROM admins WHERE id=?", adminId); if (!row || !row.totp_secret) throw new Error("Start TOTP enrollment first");
      const secret = decryptSecret(row.totp_secret, secretCipherKey); if (!verifyTotp(secret, code)) throw new Error("Invalid TOTP code");
      run("UPDATE admins SET totp_enabled=1 WHERE id=?", adminId); audit(adminId, "admin.totp.enabled", "admin", adminId, {}); return true;
    },
    disableTotp(adminId, code) {
      const row = one("SELECT totp_secret,totp_enabled FROM admins WHERE id=?", adminId); if (!row || Number(row.totp_enabled) !== 1) return true;
      const secret = decryptSecret(row.totp_secret, secretCipherKey); if (!verifyTotp(secret, code)) throw new Error("Invalid TOTP code");
      run("UPDATE admins SET totp_secret=NULL,totp_enabled=0 WHERE id=?", adminId); run("DELETE FROM recovery_codes WHERE admin_id=?", adminId); audit(adminId, "admin.totp.disabled", "admin", adminId, {}); return true;
    },
    rotateAdminToken(adminId, newToken) { run("UPDATE admins SET token_hash=? WHERE id=?", hashToken(newToken), adminId); audit(adminId, "admin.token.rotated", "admin", adminId, { token: "[redacted]" }); },
    listSites() { return rows("SELECT * FROM sites ORDER BY created_at DESC").map(siteFromRow); },
    getSite(siteId) { return siteFromRow(one("SELECT * FROM sites WHERE id = ?", siteId)); },
    createSite(site) { const siteId = id("site"); const timestamp = now(); run("INSERT INTO sites (id,name,slug,type,stack,status,domains_json,source_json,runtime_json,resources_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", siteId, site.name, site.slug, site.type, site.stack, "provisioning", JSON.stringify(site.domains), JSON.stringify(site.source), JSON.stringify(site.runtime), JSON.stringify(site.resources), timestamp, timestamp); audit("system", "site.created", "site", siteId, site); return this.getSite(siteId); },
    updateSite(siteId, patch) { const current = this.getSite(siteId); if (!current) return null; const next = { ...current, ...patch, updated_at: now() }; run("UPDATE sites SET name=?,slug=?,type=?,stack=?,status=?,domains_json=?,source_json=?,runtime_json=?,resources_json=?,updated_at=? WHERE id=?", next.name, next.slug, next.type, next.stack, next.status, JSON.stringify(next.domains), JSON.stringify(next.source), JSON.stringify(next.runtime), JSON.stringify(next.resources), next.updated_at, siteId); audit("system", "site.updated", "site", siteId, patch); return this.getSite(siteId); },
    removeSite(siteId) { run("DELETE FROM data_services WHERE site_id=?", siteId); run("DELETE FROM cron_jobs WHERE site_id=?", siteId); run("DELETE FROM ssh_keys WHERE site_id=?", siteId); run("DELETE FROM certificates WHERE site_id=?", siteId); run("DELETE FROM deployments WHERE site_id=?", siteId); run("DELETE FROM backups WHERE site_id=?", siteId); run("DELETE FROM sites WHERE id=?", siteId); audit("system", "site.deleted", "site", siteId, { irreversible: true }); },
    listJobs(limit = 30) { return rows("SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?", limit).map(jobFromRow); },
    getJob(jobId) { return jobFromRow(one("SELECT * FROM jobs WHERE id=?", jobId)); },
    createJob(kind, siteId, input) { const jobId = id("job"); run("INSERT INTO jobs (id,kind,site_id,status,progress,input_json,created_at) VALUES (?,?,?,?,?,?,?)", jobId, kind, siteId ?? null, "queued", 0, JSON.stringify(input ?? {}), now()); return this.getJob(jobId); },
    requeueJob(jobId) { run("UPDATE jobs SET status='queued',progress=0,error=NULL,started_at=NULL,finished_at=NULL WHERE id=?", jobId); return this.getJob(jobId); },
    startJob(jobId) { run("UPDATE jobs SET status='running',started_at=? WHERE id=?", now(), jobId); },
    finishJob(jobId, output) { run("UPDATE jobs SET status='completed',progress=100,output_json=?,finished_at=? WHERE id=?", JSON.stringify(output ?? {}), now(), jobId); },
    failJob(jobId, error) { run("UPDATE jobs SET status='failed',error=?,finished_at=? WHERE id=?", String(error), now(), jobId); },
    addDeployment(siteId, source, commitRef, releaseName, status = "queued") { const deploymentId = id("deploy"); run("INSERT INTO deployments (id,site_id,source,commit_ref,release_name,status,created_at) VALUES (?,?,?,?,?,?,?)", deploymentId, siteId, source, commitRef ?? "", releaseName ?? "", status, now()); return deploymentId; },
    updateDeployment(deploymentId, status) { run("UPDATE deployments SET status=? WHERE id=?", status, deploymentId); },
    listDeployments(siteId) { return rows("SELECT * FROM deployments WHERE site_id=? ORDER BY created_at DESC", siteId); },
    addBackup(siteId, kind, destination, manifest, status = "queued") { const backupId = id("backup"); run("INSERT INTO backups (id,site_id,kind,destination,status,manifest_json,created_at) VALUES (?,?,?,?,?,?,?)", backupId, siteId, kind, destination, status, JSON.stringify(manifest), now()); return backupId; },
    updateBackup(backupId, status, manifest) { run("UPDATE backups SET status=?,manifest_json=? WHERE id=?", status, JSON.stringify(manifest ?? {}), backupId); },
    listBackups(siteId) { return rows("SELECT * FROM backups WHERE site_id=? ORDER BY created_at DESC", siteId).map((row) => ({ ...row, manifest: parseJson(row.manifest_json, {}) })); },
    addDataService(siteId, engine, name, username, externalAccess = false) { const serviceId = id("data"); run("INSERT INTO data_services (id,site_id,engine,name,username,external_access,created_at) VALUES (?,?,?,?,?,?,?)", serviceId, siteId, engine, name, username, externalAccess ? 1 : 0, now()); return one("SELECT * FROM data_services WHERE id=?", serviceId); },
    listDataServices(siteId) { return rows("SELECT id,site_id,engine,name,username,external_access,created_at FROM data_services WHERE site_id=? ORDER BY created_at", siteId); },
    removeDataService(siteId, serviceId) { run("DELETE FROM data_services WHERE id=? AND site_id=?", serviceId, siteId); return true; },
    addCron(siteId, name, expression, command) { const cronId = id("cron"); run("INSERT INTO cron_jobs (id,site_id,name,expression,command,created_at) VALUES (?,?,?,?,?,?)", cronId, siteId, name, expression, command, now()); return one("SELECT * FROM cron_jobs WHERE id=?", cronId); },
    listCron(siteId) { return rows("SELECT id,site_id,name,expression,command,enabled,created_at FROM cron_jobs WHERE site_id=? ORDER BY created_at", siteId); },
    deleteCron(siteId, cronId) { run("DELETE FROM cron_jobs WHERE id=? AND site_id=?", cronId, siteId); return true; },
    addSshKey(siteId, label, publicKey, fingerprint) { const keyId = id("ssh"); run("INSERT INTO ssh_keys (id,site_id,label,public_key,fingerprint,created_at) VALUES (?,?,?,?,?,?)", keyId, siteId, label, publicKey, fingerprint, now()); return one("SELECT id,site_id,label,fingerprint,created_at FROM ssh_keys WHERE id=?", keyId); },
    listSshKeys(siteId) { return rows("SELECT id,site_id,label,fingerprint,created_at FROM ssh_keys WHERE site_id=? ORDER BY created_at DESC", siteId); },
    addCertificate(siteId, mode, domains, expiresAt = null, status = "active") { const certificateId = id("cert"); run("INSERT INTO certificates (id,site_id,mode,domains_json,status,expires_at,created_at) VALUES (?,?,?,?,?,?,?)", certificateId, siteId, mode, JSON.stringify(domains), status, expiresAt, now()); return one("SELECT * FROM certificates WHERE id=?", certificateId); },
    updateCertificate(certificateId, status, expiresAt = null) { run("UPDATE certificates SET status=?,expires_at=? WHERE id=?", status, expiresAt, certificateId); return one("SELECT id,site_id,mode,domains_json,status,expires_at,created_at FROM certificates WHERE id=?", certificateId); },
    listCertificates(siteId) { return rows("SELECT id,site_id,mode,domains_json,status,expires_at,created_at FROM certificates WHERE site_id=? ORDER BY created_at DESC", siteId).map((row) => ({ ...row, domains: parseJson(row.domains_json, []) })); },
    addMetricSample(sample) {
      run("INSERT INTO metric_samples (id,sampled_at,load1,memory_free_mb,memory_used_percent,disk_free_mb,disk_used_percent) VALUES (?,?,?,?,?,?,?)", id("metric"), sample.sampledAt ?? now(), Number(sample.load1 ?? 0), Math.max(0, Math.round(Number(sample.memoryFreeMb ?? 0))), Number(sample.memoryUsedPercent ?? 0), Math.max(0, Math.round(Number(sample.diskFreeMb ?? 0))), Number(sample.diskUsedPercent ?? 0));
      run("DELETE FROM metric_samples WHERE id NOT IN (SELECT id FROM metric_samples ORDER BY sampled_at DESC LIMIT 288)");
    },
    listMetricSamples(limit = 96) { return rows("SELECT id,sampled_at,load1,memory_free_mb,memory_used_percent,disk_free_mb,disk_used_percent FROM metric_samples ORDER BY sampled_at DESC LIMIT ?", Math.max(1, Math.min(288, Number(limit) || 96))).reverse(); },
    listAudit(limit = 80) { return rows("SELECT * FROM audit ORDER BY created_at DESC LIMIT ?", limit).map((row) => ({ ...row, details: parseJson(row.details_json, {}) })); },
    listWebhooks() { return rows("SELECT id,url,events_json,active,created_at FROM webhooks ORDER BY created_at DESC").map((row) => ({ ...row, events: parseJson(row.events_json, []) })); },
    addWebhook(url, secret, events) { const webhookId = id("hook"); run("INSERT INTO webhooks (id,url,secret,events_json,created_at) VALUES (?,?,?,?,?)", webhookId, url, encryptSecret(String(secret), secretCipherKey), JSON.stringify(events), now()); return webhookId; },
    addCredential(label, kind, secret) { const credentialId = id("cred"); const createdAt = now(); run("INSERT INTO credentials (id,label,kind,secret_enc,created_at) VALUES (?,?,?,?,?)", credentialId, label, kind, encryptSecret(secret, secretCipherKey), createdAt); audit("system", "credential.created", "credential", credentialId, { kind, secret: "[redacted]" }); return { id: credentialId, label, kind, created_at: createdAt }; },
    listCredentials() { return rows("SELECT id,label,kind,created_at FROM credentials ORDER BY created_at DESC"); },
    getCredentialSecret(credentialId) { const row = one("SELECT kind,secret_enc FROM credentials WHERE id=?", credentialId); if (!row) throw new Error("Credential not found"); return { kind: row.kind, secret: decryptSecret(row.secret_enc, secretCipherKey) }; },
    dashboard() { return { sites: one("SELECT COUNT(*) AS count FROM sites").count, online: one("SELECT COUNT(*) AS count FROM sites WHERE status='online'").count, queuedJobs: one("SELECT COUNT(*) AS count FROM jobs WHERE status IN ('queued','running')").count, failedJobs: one("SELECT COUNT(*) AS count FROM jobs WHERE status='failed'").count, databases: one("SELECT COUNT(*) AS count FROM data_services").count, profile: "micro", panelMemoryTargetMb: 256 }; },
    audit
  };
}
