import fs from "node:fs";
import os from "node:os";
import process from "node:process";
import { execFileSync } from "node:child_process";

const release = fs.existsSync("/etc/os-release") ? fs.readFileSync("/etc/os-release", "utf8") : "";
const fields = Object.fromEntries(release.split("\n").filter(Boolean).map((line) => { const index = line.indexOf("="); return [line.slice(0, index), line.slice(index + 1).replaceAll('"', "")]; }));
const memMb = Math.round(os.totalmem() / 1024 / 1024);
const cgroup = fs.existsSync("/sys/fs/cgroup/cgroup.controllers");
const commandAvailable = (name) => { try { execFileSync("which", [name], { stdio: "ignore" }); return true; } catch { return false; } };
const nodeMajor = Number(process.versions.node.split(".")[0]);
const report = {
  ok: fields.ID === "ubuntu" && fields.VERSION_ID === "24.04" && process.arch === "x64" && cgroup && nodeMajor >= 26,
  os: { id: fields.ID, version: fields.VERSION_ID, pretty: fields.PRETTY_NAME },
  architecture: process.arch,
  memoryMb: memMb,
  cgroupV2: cgroup,
  node: process.version,
  profile: memMb <= 1536 ? "micro" : memMb <= 6144 ? "small" : "custom",
  hostCapabilities: Object.fromEntries(["nginx", "php-fpm8.3", "systemctl", "mariadbd", "postgres", "redis-server", "docker"].map((name) => [name, commandAvailable(name)]).concat([["openlitespeed", commandAvailable("openlitespeed") || fs.existsSync("/usr/local/lsws/bin/openlitespeed")]])),
  checks: { cleanUbuntu2404: fields.ID === "ubuntu" && fields.VERSION_ID === "24.04", amd64: process.arch === "x64", cgroupV2: cgroup, memoryFloor: memMb >= 1024, node26: nodeMajor >= 26 }
};
console.log(JSON.stringify(report, null, 2));
if (process.argv.includes("--strict") && !report.ok) process.exitCode = 1;
