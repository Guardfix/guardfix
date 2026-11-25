import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { walk, packages, secrets, supabaseRls, compareVersions, fixedVersion, ownerColumn } from "../src/scan.js";
import { spawnSync } from "node:child_process";
import { check, grade, prompt, card, badge, main } from "../src/cli.js";

const jwt = (role) => ["eyJhbGciOiJIUzI1NiJ9", Buffer.from(JSON.stringify({ role, iss: "supabase" })).toString("base64url"),
  "c2lnbmF0dXJlc2lnbmF0dXJl"].join(".");

function project() {
  const root = mkdtempSync(join(tmpdir(), "gf-"));
  writeFileSync(join(root, "package-lock.json"), JSON.stringify({ lockfileVersion: 3, packages: {
    "": { name: "app" },
    "node_modules/axios": { version: "1.6.0" },
    "node_modules/vitest": { version: "1.0.0", dev: true },
    "node_modules/@scope/lib": { version: "2.0.0" },
  } }));
  mkdirSync(join(root, "src"));
  writeFileSync(join(root, "src", "supabase.ts"), `export const key = "${jwt("service_role")}";\nexport const anon = "${jwt("anon")}";\n`);
  writeFileSync(join(root, ".env.example"), "OPENAI_API_KEY=sk-proj-" + "a".repeat(36) + "\n");
  mkdirSync(join(root, "supabase", "migrations"), { recursive: true });
  writeFileSync(join(root, "supabase", "migrations", "001.sql"),
    "create table public.profiles (id uuid);\ncreate table notes (id int);\nalter table public.notes enable row level security;\n");
  mkdirSync(join(root, "node_modules", "x"), { recursive: true });
  writeFileSync(join(root, "node_modules", "x", "k.js"), "sk-ant-" + "a".repeat(40));
  return root;
}

const OSV = {
  "GHSA-axio": { id: "GHSA-axio", summary: "axios SSRF", database_specific: { severity: "HIGH" },
    affected: [{ package: { name: "axios" }, ranges: [{ events: [{ introduced: "0" }, { fixed: "1.7.4" }] }] }] },
  "GHSA-vite": { id: "GHSA-vite", summary: "vitest RCE", database_specific: { severity: "CRITICAL" },
    affected: [{ package: { name: "vitest" }, ranges: [{ events: [{ introduced: "0" }, { fixed: "1.6.1" }] }] }] },
};

async function fakeFetch(url, init) {
  if (url.endsWith("/querybatch")) {
    const { queries } = JSON.parse(init.body);
    const hit = { axios: "GHSA-axio", vitest: "GHSA-vite" };
    return { ok: true, json: async () => ({ results: queries.map((q) => ({ vulns: hit[q.package.name] ? [{ id: hit[q.package.name] }] : [] })) }) };
  }
  const id = decodeURIComponent(url.split("/vulns/")[1]);
  return { ok: Boolean(OSV[id]), json: async () => OSV[id] };
}

test("lockfiles of every manager", () => {
  const root = mkdtempSync(join(tmpdir(), "gf-"));
  writeFileSync(join(root, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n\npackages:\n\n  '@scope/a@1.2.3':\n    resolution: {}\n\n  lodash@4.17.20:\n    resolution: {}\n\nsnapshots:\n\n  lodash@4.17.20: {}\n");
  writeFileSync(join(root, "yarn.lock"), '"minimist@^1.2.0", minimist@^1.2.5:\n  version "1.2.5"\n\n"@babel/core@^7":\n  version "7.1.0"\n');
  writeFileSync(join(root, "bun.lock"), '{ "packages": { "ms": ["ms@2.0.0", "", {}, "sha"], "@x/y": ["@x/y@1.0.0", ""], } }');
  writeFileSync(join(root, "uv.lock"), '[[package]]\nname = "jinja2"\nversion = "3.1.2"\n');
  writeFileSync(join(root, "requirements.txt"), "flask==2.0.1\nrequests>=2\n");
  const got = packages(root, walk(root)).packages.map((p) => `${p.ecosystem}:${p.name}@${p.version}`).sort();
  assert.deepEqual(got, ["PyPI:flask@2.0.1", "PyPI:jinja2@3.1.2", "npm:@babel/core@7.1.0", "npm:@scope/a@1.2.3",
    "npm:@x/y@1.0.0", "npm:lodash@4.17.20", "npm:minimist@1.2.5", "npm:ms@2.0.0"]);
});

test("pnpm v9: quoted scoped keys, peer suffixes, dev split from importers", () => {
  const root = mkdtempSync(join(tmpdir(), "gf-"));
  writeFileSync(join(root, "pnpm-lock.yaml"), [
    'lockfileVersion: "9.0"', "", "importers:", "  .:", "    dependencies:", '      "@clack/prompts":', "        specifier: ^0.10.1",
    "        version: 0.10.1", "      react-dom:", "        specifier: ^18", "        version: 18.2.0(react@18.2.0)",
    "    devDependencies:", "      vitest:", "        specifier: ^1", "        version: 1.0.0", "", "packages:", "",
    '  "@clack/prompts@0.10.1":', "    resolution: {}", "", "  picocolors@1.1.1:", "    resolution: {}", "", "  react-dom@18.2.0:",
    "    resolution: {}", "", "  vitest@1.0.0:", "    resolution: {}", "", "  tinypool@0.8.0:", "    resolution: {}", "", "snapshots:", "",
    '  "@clack/prompts@0.10.1":', "    dependencies:", "      picocolors: 1.1.1", "", "  picocolors@1.1.1: {}", "",
    "  react-dom@18.2.0(react@18.2.0):", "    dependencies:", "      picocolors: 1.1.1", "",
    "  vitest@1.0.0:", "    dependencies:", "      tinypool: 0.8.0", "      picocolors: 1.1.1", "", "  tinypool@0.8.0: {}", ""].join("\n"));
  const got = Object.fromEntries(packages(root, walk(root)).packages.map((p) => [`${p.name}@${p.version}`, p.dev]));
  assert.deepEqual(got, { "@clack/prompts@0.10.1": false, "picocolors@1.1.1": false, "react-dom@18.2.0": false, "vitest@1.0.0": true, "tinypool@0.8.0": true });
});

test("pnpm v6: explicit dev flags", () => {
  const root = mkdtempSync(join(tmpdir(), "gf-"));
  writeFileSync(join(root, "pnpm-lock.yaml"), "lockfileVersion: '6.0'\n\npackages:\n\n  /@babel/core@7.1.0:\n    resolution: {}\n    dev: true\n\n  /axios@1.6.0:\n    resolution: {}\n    dev: false\n");
  const got = Object.fromEntries(packages(root, walk(root)).packages.map((p) => [`${p.name}@${p.version}`, p.dev]));
  assert.deepEqual(got, { "@babel/core@7.1.0": true, "axios@1.6.0": false });
});

test("a private key header without a key body is not a leak", () => {
  const root = mkdtempSync(join(tmpdir(), "gf-"));
  mkdirSync(join(root, "src"));
  const head = ["-----BEGIN", "PRIVATE KEY-----"].join(" ");  // split so secret scanners do not flag this test
  writeFileSync(join(root, "src", "validate.ts"), `if (!v.startsWith("${head}")) throw new Error("bad key");\n`);
  writeFileSync(join(root, "src", "real.ts"), `const k = "${head}\\n${"A".repeat(64)}\\n";\n`);
  const found = secrets(root, walk(root));
  assert.deepEqual(found.map((f) => f.file), [join("src", "real.ts")]);
});

test("versions and fixes", () => {
  assert.ok(compareVersions("1.10.0", "1.9.9") > 0 && compareVersions("2.0.0-rc.1", "2.0.0") < 0);
  assert.equal(fixedVersion(OSV["GHSA-axio"], { name: "axios", version: "1.6.0" }), "1.7.4");
  assert.equal(fixedVersion(OSV["GHSA-axio"], { name: "axios", version: "1.8.0" }), null);
});

test("keys are found, masked, and examples and node_modules are skipped", () => {
  const root = project();
  const found = secrets(root, walk(root));
  assert.equal(found.length, 1);
  assert.equal(found[0].id, "supabase-service-role");
  assert.match(found[0].title, /client code/);
  assert.ok(!found[0].value.includes("c2lnbmF0dXJl"));
});

test("supabase tables without RLS", () => {
  const root = project();
  assert.deepEqual(supabaseRls(root, walk(root)).map((f) => f.table), ["profiles"]);
});

test("full check: grade, dev deps apart, prompt, card, badge", async () => {
  const r = await check(project(), { fetch: fakeFetch });
  assert.equal(r.grade, "F");
  assert.deepEqual(r.findings.map((f) => f.id).sort(), ["GHSA-axio", "supabase-no-rls", "supabase-service-role"]);
  assert.equal(r.dev.length, 1);
  assert.equal(r.index.yours, 1);
  const p = prompt(r);
  assert.match(p, /axios: 1\.6\.0 -> 1\.7\.4/);
  assert.match(p, /rotate each key/);
  assert.match(p, /Never print the value of a key/);
  assert.match(p, /profiles .*no owner column found/);
  assert.ok(!p.includes("vitest"));
  assert.match(card(r), /GUARDFIX SECURITY GRADE/);
  assert.match(badge(r), /GuardFix-F-red/);
  assert.match(card({ ...r, grade: "A" }, "F"), /was <tspan font-weight="700">F<\/tspan> → now/);
  assert.doesNotMatch(card(r, "F"), /was/);
});

test("upgrade target skips a fixed version that has its own advisory", async () => {
  const vulns = {  // 1.0.0 -> first fix 1.1.0, but 1.1.0 is hit by the next advisory, fixed in 1.1.1
    A: { id: "A", database_specific: { severity: "HIGH" }, affected: [{ package: { name: "p" }, ranges: [{ events: [{ introduced: "0" }, { fixed: "1.1.0" }] }] }] },
    B: { id: "B", database_specific: { severity: "MODERATE" }, affected: [{ package: { name: "p" }, ranges: [{ events: [{ introduced: "1.1.0" }, { fixed: "1.1.1" }] }] }] },
  };
  const fetch = async (url, init) => {
    if (url.endsWith("/querybatch")) {
      const { queries } = JSON.parse(init.body);
      return { ok: true, json: async () => ({ results: queries.map((q) => ({ vulns: q.version === "1.0.0" ? [{ id: "A" }] : q.version === "1.1.0" ? [{ id: "B" }] : [] })) }) };
    }
    const id = url.split("/vulns/")[1];
    return { ok: true, json: async () => vulns[id] };
  };
  const { advisories, safeUpgrades } = await import("../src/scan.js");
  const found = await advisories([{ ecosystem: "npm", name: "p", version: "1.0.0", dev: false, file: "package-lock.json" }], { fetch });
  assert.equal(found[0].fixed, "1.1.0");
  await safeUpgrades(found, { fetch });
  assert.equal(found[0].upgrade, "1.1.1");
});

test("grade scale", () => {
  assert.equal(grade([]), "A+");
  assert.equal(grade([{ severity: "low" }]), "A");
  assert.equal(grade(Array(3).fill({ severity: "medium" })), "C");
});

test("cli exit codes and offline mode", async () => {
  const lines = [];
  const code = await main([project(), "--offline", "--json"], { log: (s) => lines.push(s) });
  const out = JSON.parse(lines[0]);
  assert.equal(out.offline, true);
  assert.equal(code, 1);  // critical findings without the network
  assert.equal(await main(["/no/such/dir"], { log: () => {} }), 2);
});

test("a key in a git-ignored .env is where it belongs; a committed one is a leak", () => {
  const root = mkdtempSync(join(tmpdir(), "gf-"));
  const key = "sk_" + "live_" + "a1B2c3D4e5F6g7H8i9J0k1L2";
  writeFileSync(join(root, ".env"), `STRIPE_SECRET_KEY=${key}\n`);
  writeFileSync(join(root, ".env.production"), `STRIPE_SECRET_KEY=${key}\n`);
  assert.equal(secrets(root, walk(root)).length, 2);  // no git: nothing tells us it stays local
  spawnSync("git", ["init", "-q", root]);
  writeFileSync(join(root, ".gitignore"), ".env\n");
  assert.deepEqual(secrets(root, walk(root)).map((f) => f.file), [".env.production"]);
});

test("supabase: RLS enabled later, if exists, dropped tables, other schemas, owner column", () => {
  const root = mkdtempSync(join(tmpdir(), "gf-"));
  mkdirSync(join(root, "supabase", "migrations"), { recursive: true });
  writeFileSync(join(root, "supabase", "migrations", "001.sql"), [
    "create table public.todos (id bigint primary key, user_id uuid references auth.users(id) on delete cascade, title text);",
    "create table if not exists posts (id int, author_id uuid, body text);",
    "create table private.audit (id int);",
    "create table tmp (id int);",
    "-- alter table posts enable row level security;",
  ].join("\n"));
  writeFileSync(join(root, "supabase", "migrations", "002.sql"),
    "alter table if exists public.todos enable row level security;\ndrop table if exists tmp;\n" +
    "create table \"Members\" (member uuid, team int, constraint fk foreign key (member) references auth.users(id));\n");
  const got = supabaseRls(root, walk(root)).map((f) => [f.table, f.owner]);
  assert.deepEqual(got, [["posts", "author_id"], ["members", "member"]]);
  assert.equal(ownerColumn("create table x (id uuid primary key references auth.users, name text);"), "id");
  assert.equal(ownerColumn("create table x (id int, price numeric(10,2));"), null);
});

test("without the dependency lookup the grade is incomplete: no badge, no card", async () => {
  const lines = [];
  const root = project();
  await main([root, "--offline", "--json", "--card"], { log: (s) => lines.push(s) });
  const out = JSON.parse(lines[0]);
  assert.equal(out.complete, false);
  assert.equal(out.badge, null);
  assert.match(lines[1], /No card/);
  const down = async () => { throw new Error("network down"); };
  const r = await check(root, { fetch: down });
  assert.equal(r.complete, false);
  assert.match(r.osvError, /network down/);
});
