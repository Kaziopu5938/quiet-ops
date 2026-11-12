import fs from "node:fs";
import os from "node:os";
import process from "node:process";
import { execFileSync } from "node:child_process";

const release = fs.existsSync("/etc/os-release") ? fs.readFileSync("/etc/os-release", "utf8") : "";
const fields = Object.fromEntries(release.split("\n").filter(Boolean).map((line) => { const index = line.indexOf("="); return [line.slice(0, index), line.slice(index + 1).replaceAll('"', "")]; }));
const commandExists = (name) => { try { execFileSync("which", [name], { stdio: "ignore" }); return true; } catch { return false; } };
const serviceActive = (name) => { try { execFileSync("systemctl", ["is-active", "--quiet", name], { stdio: "ignore" }); return true; } catch { return false; } };
const userInGroup = (user, group) => { try { return execFileSync("id", ["-nG", user], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).split(/\s+/).includes(group); } catch { return false; } };
const required = ["node", "systemctl", "nginx", "php-fpm8.3", "git", "docker", "setfacl", "certbot", "mariadb", "mariadb-dump", "psql", "pg_dump", "redis-cli", "sshd", "cron", "flock", "timeout"];
const optional = ["openlitespeed"];
const report = {
  os: `${fields.ID ?? "unknown"} ${fields.VERSION_ID ?? "unknown"}`,
  architecture: process.arch,
  node: process.version,
  cgroupV2: fs.existsSync("/sys/fs/cgroup/cgroup.controllers"),
  required: Object.fromEntries(required.map((name) => [name, commandExists(name)])),
  optional: Object.fromEntries(optional.map((name) => [name, commandExists(name) || (name === "openlitespeed" && fs.existsSync("/usr/local/lsws/bin/openlitespeed"))])),
  services: Object.fromEntries(["nginx", "php8.3-fpm", "cron", "docker", "lsws"].map((name) => [name, serviceActive(name)])),
  permissions: { nginxWorkerCanReadSites: commandExists("setfacl") && !userInGroup("www-data", "quiet-ops"), panelCanUseAgent: userInGroup("quiet-ops", "quiet-ops-control"), nginxCannotUseAgent: !userInGroup("www-data", "quiet-ops-control") },
};
const baseOk = fields.ID === "ubuntu" && fields.VERSION_ID === "24.04" && process.arch === "x64" && report.cgroupV2 && Number(process.versions.node.split(".")[0]) >= 26 && required.every((name) => report.required[name]) && Object.entries(report.services).filter(([name]) => name !== "lsws").every(([, active]) => active) && report.permissions.nginxWorkerCanReadSites && report.permissions.panelCanUseAgent && report.permissions.nginxCannotUseAgent;
const fullOk = baseOk && optional.every((name) => report.optional[name]) && report.services.lsws;
report.ok = process.argv.includes("--full") ? fullOk : baseOk;
report.mode = process.argv.includes("--full") ? "full-ols" : "base-runtime";
console.log(JSON.stringify(report, null, 2));
if (!report.ok) process.exitCode = 1;
