import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { handle, TOOLS } from "../src/mcp.js";

const VULN = { id: "GHSA-test", summary: "SSRF in axios", database_specific: { severity: "HIGH" },
  affected: [{ package: { name: "axios" }, ranges: [{ events: [{ introduced: "0" }, { fixed: "1.7.4" }] }] }] };
async function fetch(url, init) {
  if (url.endsWith("/querybatch")) {
    const { queries } = JSON.parse(init.body);
    return { ok: true, json: async () => ({ results: queries.map((q) => ({ vulns: q.package.name === "axios" && q.version === "1.6.0" ? [{ id: "GHSA-test" }] : [] })) }) };
  }
  return { ok: true, json: async () => VULN };
}
const call = (name, args, ctx = {}) => handle({ jsonrpc: "2.0", id: 7, method: "tools/call", params: { name, arguments: args } }, { fetch, ...ctx });

test("initialize answers with tools capability and a supported protocol", async () => {
  const r = await handle({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {} } });
  assert.equal(r.result.protocolVersion, "2025-03-26");
  assert.deepEqual(r.result.capabilities, { tools: {} });
  assert.equal(r.result.serverInfo.name, "guardfix");
  const unknown = await handle({ jsonrpc: "2.0", id: 2, method: "initialize", params: { protocolVersion: "1999-01-01" } });
  assert.equal(unknown.result.protocolVersion, "2025-06-18");
});

test("notifications get no answer, unknown methods an error", async () => {
  assert.equal(await handle({ jsonrpc: "2.0", method: "notifications/initialized" }), null);
  assert.equal((await handle({ jsonrpc: "2.0", id: 3, method: "resources/list" })).error.code, -32601);
  assert.equal((await call("nope", {})).error.code, -32602);
});

test("tools/list has scan, check_package and fix_plan", async () => {
  const r = await handle({ jsonrpc: "2.0", id: 4, method: "tools/list" });
  assert.deepEqual(r.result.tools.map((t) => t.name), ["scan", "check_package", "fix_plan"]);
  assert.equal(TOOLS.length, 3);
});

test("check_package: vulnerable version gets the upgrade, clean version is safe", async () => {
  const bad = (await call("check_package", { name: "axios", version: "1.6.0" })).result;
  assert.equal(bad.structuredContent.safe, false);
  assert.equal(bad.structuredContent.upgrade, "1.7.4");
  assert.match(bad.content[0].text, /Use 1\.7\.4 or later/);
  const good = (await call("check_package", { name: "axios", version: "1.7.4" })).result;
  assert.equal(good.structuredContent.safe, true);
  const missing = (await call("check_package", { name: "axios" })).result;
  assert.equal(missing.isError, true);
});

test("scan and fix_plan read the project folder", async () => {
  const root = mkdtempSync(join(tmpdir(), "gf-mcp-"));
  mkdirSync(join(root, "supabase", "migrations"), { recursive: true });
  writeFileSync(join(root, "supabase", "migrations", "001.sql"), "create table public.notes (id uuid primary key, user_id uuid);\n");
  writeFileSync(join(root, "package-lock.json"), JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/axios": { version: "1.6.0" } } }));
  const scan = (await call("scan", {}, { cwd: root })).result;
  assert.equal(scan.structuredContent.grade, "F");
  assert.match(scan.content[0].text, /row level security/);
  assert.match(scan.content[0].text, /axios 1\.6\.0 → 1\.7\.4/);
  const plan = (await call("fix_plan", { path: root })).result;
  assert.match(plan.content[0].text, /axios: 1\.6\.0 -> 1\.7\.4/);
  const gone = (await call("scan", { path: join(root, "missing") })).result;
  assert.equal(gone.isError, true);
});

test("npx guardfix mcp speaks JSON-RPC over stdio, one line per message", async () => {
  const child = spawn(process.execPath, [new URL("../bin/guardfix.js", import.meta.url).pathname, "mcp"], { stdio: ["pipe", "pipe", "inherit"] });
  let out = "";
  child.stdout.on("data", (d) => { out += d; });
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18" } }) + "\n");
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
  child.stdin.write("not json\n");
  child.stdin.end(JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }) + "\n");
  const code = await new Promise((done) => child.on("close", done));
  const lines = out.trim().split("\n").map((l) => JSON.parse(l));
  assert.equal(code, 0);
  assert.equal(lines.length, 3);
  assert.equal(lines.find((l) => l.id === 1).result.serverInfo.name, "guardfix");
  assert.equal(lines.find((l) => l.error)?.error.code, -32700);
  assert.equal(lines.find((l) => l.id === 2).result.tools.length, 3);
});
