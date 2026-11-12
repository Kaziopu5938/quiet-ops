import test from "node:test";
import assert from "node:assert/strict";
import { slugify, validateCronInput, validateSiteInput, validateEngine, validateDeployInput } from "../server/domain.mjs";

test("slugify creates stable safe identifiers", () => {
  assert.equal(slugify("My Portfolio / 2026"), "my-portfolio-2026");
});

test("site validation enforces workload and stack compatibility", () => {
  const site = validateSiteInput({ name: "Docs", type: "wordpress", stack: "ols", domains: ["example.com"] });
  assert.equal(site.slug, "docs");
  assert.equal(site.stack, "ols");
  assert.throws(() => validateSiteInput({ name: "Bad", type: "wordpress", stack: "node" }), /WordPress/);
  assert.throws(() => validateSiteInput({ name: "Bad", type: "static", domains: ["not a domain"] }), /Invalid domain/);
});

test("data service engines are allowlisted", () => {
  assert.equal(validateEngine("mariadb"), "mariadb");
  assert.throws(() => validateEngine("shell"), /Unsupported engine/);
});

test("cron input is a five-field allowlisted command", () => {
  const cron = validateCronInput({ name: "wp-cron", expression: "*/5 * * * *", command: "wp cron event run --due-now" });
  assert.equal(cron.expression, "*/5 * * * *");
  assert.throws(() => validateCronInput({ expression: "@reboot", command: "wp cron event run" }), /five numeric fields/);
  assert.throws(() => validateCronInput({ expression: "* * * * *", command: "sh -c id" }), /allowlisted/);
});

test("site metadata cannot smuggle credentials or escape runtime roots", () => {
  assert.throws(() => validateSiteInput({ name: "Secret", source: { repo: "https://example.com/repo.git", token: "plain" } }), /credentials/);
  assert.throws(() => validateSiteInput({ name: "Escape", type: "node", runtime: { entry: "../../etc/passwd" } }), /inside the site release/);
  assert.throws(() => validateSiteInput({ name: "Unit injection", type: "node", runtime: { entry: "server.js --inspect" } }), /inside the site release/);
  assert.throws(() => validateSiteInput({ name: "Port", type: "node", runtime: { port: "80" } }), /between 1024/);
  const site = validateSiteInput({ name: "Safe Node", type: "node", runtime: { entry: "server.js", port: "3100" }, resources: { memoryMb: 512, cpuPercent: 50, diskMb: 4096 } });
  assert.equal(site.runtime.port, "3100");
  assert.equal(site.resources.memoryMb, 512);
  const container = validateSiteInput({ name: "Container Node", type: "next", runtime: { isolation: "docker", image: "node:22-alpine" } });
  assert.equal(container.runtime.isolation, "docker");
  assert.throws(() => validateSiteInput({ name: "Bad Image", type: "node", runtime: { isolation: "docker", image: "node image" } }), /image reference/);
});

test("Git deployment input is typed and credential-free", () => {
  const deploy = validateDeployInput({ repo: "https://git.example.com/team/site.git", branch: "release", build: "next" });
  assert.equal(deploy.sourceSpec.repo, "https://git.example.com/team/site.git");
  assert.throws(() => validateDeployInput({ repo: "http://git.example.com/site.git" }), /HTTPS/);
  assert.throws(() => validateDeployInput({ repo: "https://user:pass@git.example.com/site.git" }), /protected credential/);
  assert.throws(() => validateDeployInput({ repo: "https://git.example.com/site.git", branch: "bad branch" }), /branch/);
});
