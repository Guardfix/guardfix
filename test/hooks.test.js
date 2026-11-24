import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { afterEdit, pins, review, decision } from "../src/guard.js";
import { watch, stateFile, EVERY } from "../src/watch.js";

const jwt = (role) => ["eyJhbGciOiJIUzI1NiJ9", Buffer.from(JSON.stringify({ role, iss: "supabase" })).toString("base64url"),
  "c2lnbmF0dXJlc2lnbmF0dXJl"].join(".");
const OPENAI = "sk-proj-" + "a".repeat(40);

// OSV with one advisory per name, hitting only the listed versions
function osv(table) {
  return async (url, init) => {
    if (url.endsWith("/querybatch")) {
      const { queries } = JSON.parse(init.body);
      return { ok: true, json: async () => ({ results: queries.map((q) => ({
        vulns: (table[q.package.name]?.versions || []).includes(q.version) ? [{ id: table[q.package.name].id }] : [] })) }) };
    }
    const id = decodeURIComponent(url.split("/vulns/")[1]);
    const [name, t] = Object.entries(table).find(([, v]) => v.id === id) || [];
    return { ok: Boolean(t), json: async () => ({ id, summary: `${name} hole`, database_specific: { severity: t.severity },
      affected: [{ package: { name }, ranges: [{ events: [{ introduced: "0" }, { fixed: t.fixed }] }] }] }) };
  };
}
const TABLE = { axios: { id: "GHSA-axio", severity: "HIGH", fixed: "1.7.4", versions: ["1.6.0"] },
  next: { id: "GHSA-next", severity: "CRITICAL", fixed: "14.2.25", versions: ["14.1.0"] } };

function repo() {
  const root = mkdtempSync(join(tmpdir(), "gf-hook-"));
  spawnSync("git", ["init", "-q", root]);
  writeFileSync(join(root, ".gitignore"), ".env\n");
  mkdirSync(join(root, "src"));
  return root;
}

test("afterEdit applies Write, Edit and MultiEdit the way the tools do", () => {
  assert.equal(afterEdit("Write", { content: "x" }, "old"), "x");
  assert.equal(afterEdit("Edit", { old_string: "a", new_string: "b" }, "a a"), "b a");
  assert.equal(afterEdit("Edit", { old_string: "a", new_string: "b", replace_all: true }, "a a"), "b b");
  assert.equal(afterEdit("Edit", { old_string: "$&", new_string: "$1" }, "x $& y"), "x $1 y");
  assert.equal(afterEdit("MultiEdit", { edits: [{ old_string: "a", new_string: "b" }, { old_string: "b b", new_string: "c" }] }, "a b"), "c");
  assert.equal(afterEdit("Edit", { old_string: "zzz", new_string: "b" }, "a"), null);
  assert.equal(afterEdit("Bash", { command: "ls" }, ""), null);
});

test("a key written into client code is stopped, with what to do instead", async () => {
  const root = repo();
  const r = await review({ root, tool: "Write", input: { file_path: join(root, "src", "supabase.ts"),
    content: `export const key = "${jwt("service_role")}";\nexport const anon = "${jwt("anon")}";\n` }, offline: true });
  assert.equal(r.problems.length, 1);
  assert.match(r.problems[0], /service_role key in client code written into src\/supabase\.ts:1/);
  assert.match(r.problems[0], /environment variable on the server side/);
  assert.doesNotMatch(r.problems[0], new RegExp(jwt("service_role").slice(20, 60)));  // masked
  const d = decision(r);
  assert.equal(d.hookSpecificOutput.permissionDecision, "deny");
  assert.equal(d.systemMessage, "GuardFix stopped a leaked key in src/supabase.ts");
});

test("a key that was already there, or one in a git-ignored .env, is let through", async () => {
  const root = repo();
  writeFileSync(join(root, "src", "ai.ts"), `const k = "${OPENAI}";\n`);
  const edit = await review({ root, tool: "Edit", input: { file_path: join(root, "src", "ai.ts"), old_string: "const k",
    new_string: "export const k" }, offline: true });
  assert.deepEqual(edit.problems, []);
  const env = await review({ root, tool: "Write", input: { file_path: join(root, ".env"), content: `OPENAI_API_KEY=${OPENAI}\n` }, offline: true });
  assert.deepEqual(env.problems, []);
  const committed = await review({ root, tool: "Write", input: { file_path: join(root, ".env.local"), content: `OPENAI_API_KEY=${OPENAI}\n` }, offline: true });
  assert.match(committed.problems[0], /not ignored by git/);
  const outside = await review({ root, tool: "Write", input: { file_path: join(tmpdir(), "elsewhere.ts"), content: `"${OPENAI}"` }, offline: true });
  assert.deepEqual(outside.problems, []);
});

test("a migration that creates a public table without RLS is stopped, one that enables it is not", async () => {
  const root = repo();
  mkdirSync(join(root, "supabase", "migrations"), { recursive: true });
  writeFileSync(join(root, "supabase", "migrations", "001.sql"), "create table public.old (id int);\n");
  const file = join(root, "supabase", "migrations", "002.sql");
  const bad = await review({ root, tool: "Write", offline: true, input: { file_path: file,
    content: "create table public.notes (id uuid primary key, user_id uuid references auth.users, body text);\n" } });
  assert.equal(bad.problems.length, 1);  // "old" was there before: not this edit's doing
  assert.match(bad.problems[0], /"notes".*auth\.uid\(\) = user_id/s);
  const good = await review({ root, tool: "Write", offline: true, input: { file_path: file,
    content: "create table public.notes (id uuid);\nalter table public.notes enable row level security;\n" } });
  assert.deepEqual(good.problems, []);
  const privateSchema = await review({ root, tool: "Write", offline: true, input: { file_path: file, content: "create table private.audit (id int);\n" } });
  assert.deepEqual(privateSchema.problems, []);
});

test("a dependency pinned to a vulnerable version is stopped with the version to use", async () => {
  const root = repo();
  const file = join(root, "package.json");
  writeFileSync(file, JSON.stringify({ dependencies: { next: "14.1.0" } }, null, 2));
  const fetch = osv(TABLE);
  const added = await review({ root, tool: "Write", fetch, input: { file_path: file,
    content: JSON.stringify({ dependencies: { next: "14.1.0", axios: "1.6.0", react: "^18.2.0" }, devDependencies: { vitest: "1.0.0" } }) } });
  assert.equal(added.problems.length, 1);  // next was already pinned: the session check reports it, not the guard
  assert.match(added.problems[0], /axios 1\.6\.0 in package\.json has 1 known vulnerability, worst high \(GHSA-axio\): use 1\.7\.4 or newer/);
  const fine = await review({ root, tool: "Write", fetch, input: { file_path: file, content: JSON.stringify({ dependencies: { axios: "1.7.4" } }) } });
  assert.deepEqual(fine.problems, []);
  const down = await review({ root, tool: "Write", fetch: async () => { throw new Error("offline"); },
    input: { file_path: file, content: JSON.stringify({ dependencies: { axios: "1.6.0" } }) } });
  assert.deepEqual(down.problems, []);  // no network: let it through
});

test("pins reads exact production pins only", () => {
  assert.deepEqual([...pins("package.json", JSON.stringify({ dependencies: { a: "1.2.3", b: "^1.0.0", c: "=2.0.0", d: "latest" } })).keys()],
    ["npm|a", "npm|c"]);
  assert.deepEqual([...pins("requirements-dev.txt", "Flask==3.0.0\nrequests>=2\nuvicorn[standard]==0.30.0\n").keys()],
    ["PyPI|flask", "PyPI|uvicorn"]);
  assert.equal(pins("README.md", "a==1.0.0").size, 0);
});

test("the session check says what is new since last time, and is quiet otherwise", async () => {
  const root = repo();
  const home = mkdtempSync(join(tmpdir(), "gf-home-"));
  const lock = (v) => writeFileSync(join(root, "package-lock.json"), JSON.stringify({ lockfileVersion: 3, packages: {
    "": { name: "app" }, "node_modules/axios": { version: v }, "node_modules/next": { version: "14.1.0" } } }));
  lock("1.7.4");
  const t0 = Date.UTC(2026, 10, 18);
  const first = await watch(root, { fetch: osv(TABLE), now: t0, home });
  assert.match(first.message, /watching this project: 1 vulnerable package with a fix \(next 14\.1\.0 \(critical\) → 14\.2\.25\)/);
  assert.ok(existsSync(stateFile(root, home)));
  assert.equal(await watch(root, { fetch: osv(TABLE), now: t0 + 1000, home }), null);  // same lock, checked recently
  assert.equal(await watch(root, { fetch: osv(TABLE), now: t0 + EVERY + 1, home }), null);  // nothing new
  const newAdvisory = { ...TABLE, axios: { ...TABLE.axios, versions: ["1.6.0", "1.7.4"], fixed: "1.8.2" } };
  const later = await watch(root, { fetch: osv(newAdvisory), now: t0 + 2 * EVERY + 2, home });
  assert.match(later.message, /^GuardFix: new since 2026-11-18 — axios 1\.7\.4 \(high\) → 1\.8\.2/);
  assert.match(later.context, /1 new high or critical vulnerability was found/);
  lock("1.6.0");  // a changed lock is looked up again at once
  const again = await watch(root, { fetch: osv(newAdvisory), now: t0 + 2 * EVERY + 3, home });
  assert.match(again.message, /axios 1\.6\.0 \(high\)/);
  assert.equal(await watch(root, { fetch: async () => { throw new Error("down"); }, now: t0 + 9 * EVERY, home }), null);
  assert.deepEqual(JSON.parse(readFileSync(stateFile(root, home), "utf8")).known, ["axios@1.6.0|GHSA-axio", "next@14.1.0|GHSA-next"]);
});

test("the hooks answer Claude Code in its format and never fail an edit", () => {
  const root = repo();
  const hook = (name, event, env = {}) => spawnSync("node", [join(import.meta.dirname, "..", "hooks", name)],
    { input: JSON.stringify(event), encoding: "utf8", env: { ...process.env, GUARDFIX_OFFLINE: "1", ...env } });
  const denied = hook("pre-write.js", { cwd: root, tool_name: "Write",
    tool_input: { file_path: join(root, "src", "ai.ts"), content: `const k = "${OPENAI}";\n` } });
  assert.equal(denied.status, 0);
  assert.equal(JSON.parse(denied.stdout).hookSpecificOutput.permissionDecision, "deny");
  const off = hook("pre-write.js", { cwd: root, tool_name: "Write", tool_input: { file_path: join(root, "src", "ai.ts"), content: `"${OPENAI}"` } },
    { GUARDFIX_GUARD: "0" });
  assert.equal(off.stdout, "");
  const garbage = spawnSync("node", [join(import.meta.dirname, "..", "hooks", "pre-write.js")], { input: "not json", encoding: "utf8" });
  assert.equal(garbage.status, 0);
  const start = hook("session-start.js", { cwd: root, source: "startup" }, { GUARDFIX_HOME: mkdtempSync(join(tmpdir(), "gf-h-")) });
  assert.equal(start.status, 0);  // no lockfile: quiet
  assert.equal(start.stdout, "");
});
