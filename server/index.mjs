import path from "node:path";
import fs from "node:fs";
import crypto from "node:crypto";
import net from "node:net";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createApp } from "./app.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const port = Number(process.env.PANEL_PORT ?? 8787);
const bind = process.env.PANEL_BIND ?? "127.0.0.1";
const dataDir = process.env.PANEL_DATA_DIR ?? path.join(root, "data");
// A clean install intentionally starts without an admin. The browser setup
// flow creates the first account; an explicit token remains supported for
// unattended/test installs and existing upgrades.
const token = process.env.PANEL_ADMIN_TOKEN ?? "";
const firstInstall = !fs.existsSync(path.join(dataDir, "panel.sqlite"));
const liveHost = process.env.PANEL_LIVE === "1";
const backupKey = process.env.PANEL_BACKUP_KEY_FILE ? fs.readFileSync(process.env.PANEL_BACKUP_KEY_FILE, "utf8").trim() : (process.env.PANEL_BACKUP_KEY ?? "");
if (liveHost) {
  if (token && (token.length < 32 || token === "dev-token-change-me")) throw new Error("PANEL_ADMIN_TOKEN must be a high-entropy value of at least 32 characters in live mode");
  if (backupKey.length < 32) throw new Error("PANEL_BACKUP_KEY must be a stable recovery key of at least 32 characters in live mode");
}
function stableSecretKey() {
  if (process.env.PANEL_SECRET_KEY_FILE) return fs.readFileSync(process.env.PANEL_SECRET_KEY_FILE, "utf8").trim();
  if (process.env.PANEL_SECRET_KEY) return process.env.PANEL_SECRET_KEY;
  const filename = path.join(dataDir, ".panel-secret");
  if (fs.existsSync(filename)) return fs.readFileSync(filename, "utf8").trim();
  const generated = crypto.randomBytes(32).toString("base64url");
  fs.mkdirSync(dataDir, { recursive: true, mode: 0o750 });
  fs.writeFileSync(filename, generated, { mode: 0o600 });
  return generated;
}
const secretKey = stableSecretKey();
function ensurePanelCertificate() {
  if (process.env.PANEL_TLS === "0") return null;
  const configuredCert = process.env.PANEL_TLS_CERT_FILE;
  const configuredKey = process.env.PANEL_TLS_KEY_FILE;
  if ((configuredCert && !configuredKey) || (!configuredCert && configuredKey)) throw new Error("PANEL_TLS_CERT_FILE and PANEL_TLS_KEY_FILE must be supplied together");
  const tlsDir = process.env.PANEL_TLS_DIR ?? path.join(dataDir, "tls");
  const certFile = configuredCert ?? path.join(tlsDir, "panel.crt");
  const keyFile = configuredKey ?? path.join(tlsDir, "panel.key");
  fs.mkdirSync(path.dirname(certFile), { recursive: true, mode: 0o750 });
  fs.mkdirSync(path.dirname(keyFile), { recursive: true, mode: 0o750 });
  if (!fs.existsSync(certFile) || !fs.existsSync(keyFile)) {
    const host = process.env.PANEL_TLS_HOST ?? (net.isIP(bind) ? bind : "localhost");
    if (!/^[A-Za-z0-9.:-]+$/.test(host)) throw new Error("PANEL_TLS_HOST contains unsupported characters");
    const san = net.isIP(host) ? `IP:${host}` : `DNS:${host}`;
    execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "365", "-keyout", keyFile, "-out", certFile, "-subj", `/CN=${host}`, "-addext", `subjectAltName=${san}`], { stdio: "ignore" });
    fs.chmodSync(keyFile, 0o600); fs.chmodSync(certFile, 0o640);
  }
  return { key: fs.readFileSync(keyFile), cert: fs.readFileSync(certFile) };
}
const tls = ensurePanelCertificate();
// Never let an environment token silently skip the browser signup on a clean
// install. Existing databases retain token authentication for upgrades.
const bootstrapToken = firstInstall ? "" : token;
const { server } = createApp({ dataDir, bootstrapToken, secretKey, liveHost, backupKey, agentSocket: process.env.PANEL_AGENT_SOCKET ?? "", tls });
server.listen(port, bind, () => console.log(`Quiet Ops listening on ${tls ? "https" : "http"}://${bind}:${port} (${liveHost ? "live host adapter" : "safe dry-run host adapter"})`));
