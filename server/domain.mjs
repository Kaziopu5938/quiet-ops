import crypto from "node:crypto";

const SITE_TYPES = new Set(["static", "wordpress", "next", "node"]);
const STACKS = new Set(["nginx", "ols", "node"]);
const ENGINES = new Set(["mariadb", "postgresql", "redis"]);

export function slugify(value) {
  return String(value ?? "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48) || `site-${crypto.randomBytes(3).toString("hex")}`;
}

export function id(prefix = "id") {
  return `${prefix}_${crypto.randomUUID().replaceAll("-", "").slice(0, 16)}`;
}

export function now() {
  return new Date().toISOString();
}

export function parseJson(value, fallback) {
  try { return JSON.parse(value); } catch { return fallback; }
}

export function validateSiteInput(input = {}) {
  const name = String(input.name ?? "").trim();
  const type = String(input.type ?? "static").toLowerCase();
  const stack = String(input.stack ?? (type === "wordpress" ? "nginx" : type === "node" || type === "next" ? "node" : "nginx")).toLowerCase();
  if (name.length < 2 || name.length > 80) throw new Error("A site name between 2 and 80 characters is required");
  if (!SITE_TYPES.has(type)) throw new Error(`Unsupported site type: ${type}`);
  if (!STACKS.has(stack)) throw new Error(`Unsupported stack: ${stack}`);
  if (type === "wordpress" && !["nginx", "ols"].includes(stack)) throw new Error("WordPress uses nginx or ols");
  if ((type === "next" || type === "node") && stack !== "node") throw new Error("Node workloads use the node stack");
  const domains = Array.isArray(input.domains) ? input.domains.map(String).map((x) => x.trim().toLowerCase()).filter(Boolean).slice(0, 20) : [];
  for (const domain of domains) {
    if (!/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain)) throw new Error(`Invalid domain: ${domain}`);
  }
  const sourceInput = input.source && typeof input.source === "object" ? input.source : {};
  const forbiddenSourceKeys = Object.keys(sourceInput).filter((key) => /pass|secret|token|credential|privatekey/i.test(key));
  if (forbiddenSourceKeys.length) throw new Error("Repository credentials must use the protected credential store, not site metadata");
  const source = Object.fromEntries(Object.entries(sourceInput).filter(([key]) => ["repo", "branch", "ref", "provider", "path"].includes(key)).map(([key, value]) => [key, String(value).slice(0, 512)]));
  if (source.repo && !/^(https:\/\/|ssh:\/\/|git@)[^\s]+$/.test(source.repo)) throw new Error("Repository URL must use HTTPS or SSH syntax");
  if (source.repo?.startsWith("https://")) { const repository = new URL(source.repo); if (repository.username || repository.password) throw new Error("Repository credentials must use the protected credential store"); }
  const runtimeInput = input.runtime && typeof input.runtime === "object" ? input.runtime : {};
  const runtime = Object.fromEntries(Object.entries(runtimeInput).filter(([key]) => ["node", "php", "entry", "port", "mode", "isolation", "image"].includes(key)).map(([key, value]) => [key, String(value).slice(0, 128)]));
  if (runtime.entry && (runtime.entry.startsWith("/") || runtime.entry.includes("..") || !/^[a-zA-Z0-9._/-]+$/.test(runtime.entry))) throw new Error("Runtime entry must remain inside the site release");
  if (runtime.port && (!/^\d{2,5}$/.test(runtime.port) || Number(runtime.port) < 1024 || Number(runtime.port) > 65535)) throw new Error("Runtime port must be between 1024 and 65535");
  if (runtime.isolation && !["process", "docker"].includes(runtime.isolation)) throw new Error("Runtime isolation must be process or docker");
  if (runtime.image && !/^[a-zA-Z0-9][a-zA-Z0-9./:_@-]{0,190}$/.test(runtime.image)) throw new Error("Container image reference is invalid");
  const resourcesInput = input.resources && typeof input.resources === "object" ? input.resources : {};
  const resources = { profile: String(resourcesInput.profile ?? "micro"), memoryMb: Number(resourcesInput.memoryMb ?? 256), cpuPercent: Number(resourcesInput.cpuPercent ?? 25), diskMb: Number(resourcesInput.diskMb ?? 2048), keepReleases: Number(resourcesInput.keepReleases ?? 3) };
  if (!Number.isFinite(resources.memoryMb) || resources.memoryMb < 64 || resources.memoryMb > 16384) throw new Error("Memory limit must be between 64 MiB and 16 GiB");
  if (!Number.isFinite(resources.cpuPercent) || resources.cpuPercent < 1 || resources.cpuPercent > 800) throw new Error("CPU limit is outside the supported range");
  if (!Number.isFinite(resources.diskMb) || resources.diskMb < 128 || resources.diskMb > 1_000_000) throw new Error("Disk limit is outside the supported range");
  if (!Number.isInteger(resources.keepReleases) || resources.keepReleases < 2 || resources.keepReleases > 10) throw new Error("Release retention must be between 2 and 10");
  return { name, slug: slugify(name), type, stack, domains, source, runtime, resources };
}

export function validateEngine(engine) {
  if (!ENGINES.has(engine)) throw new Error(`Unsupported engine: ${engine}`);
  return engine;
}

export function validateCronInput(input = {}) {
  const name = String(input.name ?? "scheduled-job").trim().slice(0, 80);
  const expression = String(input.expression ?? "").trim();
  const command = String(input.command ?? "").trim();
  if (!name || name.length > 80 || !/^[a-zA-Z0-9][a-zA-Z0-9 ._-]*$/.test(name)) throw new Error("Cron name contains unsupported characters");
  const fields = expression.split(/\s+/);
  if (fields.length !== 5 || fields.some((field) => field.length > 32 || !/^[0-9*/,-]+$/.test(field))) throw new Error("Cron expression must contain five numeric fields");
  if (!command || command.length > 500 || /[\r\n;&|$`<>\0'\"]/.test(command)) throw new Error("Cron command must be a plain allowlisted argv");
  const argv = command.split(/\s+/);
  const allowed = new Set(["wp", "php", "node", "npm"]);
  if (argv.length > 16 || !allowed.has(argv[0])) throw new Error("Cron command executable is not allowlisted");
  if (argv.some((argument) => argument.length > 256 || argument.startsWith("/") || argument.includes(".."))) throw new Error("Cron command argument escapes the site workspace");
  return { name, expression: fields.join(" "), command: argv.join(" ") };
}

export function validateDeployInput(input = {}) {
  const sourceSpec = input.sourceSpec ?? (input.source && typeof input.source === "object" ? input.source : (input.repo ? { repo: input.repo, branch: input.branch, build: input.build, image: input.image } : null));
  if (!sourceSpec) return { ...input };
  if (Object.keys(sourceSpec).some((key) => key !== "credentialId" && /pass|secret|token|credential|privatekey/i.test(key))) throw new Error("Git credentials must use the protected credential store");
  const repo = String(sourceSpec.repo ?? "").trim();
  if (!/^https:\/\/[^\s]+$/.test(repo)) throw new Error("Git deployments require an HTTPS repository URL");
  const repository = new URL(repo); if (repository.username || repository.password) throw new Error("Git credentials must use the protected credential store");
  const branch = String(sourceSpec.branch ?? "main").trim();
  if (!branch || branch.length > 120 || /[\r\n\0\s]/.test(branch)) throw new Error("Git branch is invalid");
  const build = String(sourceSpec.build ?? "none");
  if (!new Set(["none", "node", "next"]).has(build)) throw new Error("Unsupported build profile");
  const credentialId = sourceSpec.credentialId ? String(sourceSpec.credentialId) : undefined;
  if (credentialId && !/^cred_[a-zA-Z0-9]+$/.test(credentialId)) throw new Error("Credential reference is invalid");
  return { ...input, sourceSpec: { repo, branch, build, credentialId, image: sourceSpec.image ? String(sourceSpec.image).slice(0, 191) : undefined } };
}

export function redacted(value) {
  if (!value || typeof value !== "object") return value;
  const secretWords = /pass|secret|token|key|credential/i;
  return Object.fromEntries(Object.entries(value).map(([key, val]) => [key, secretWords.test(key) ? "[redacted]" : val && typeof val === "object" ? redacted(val) : val]));
}
