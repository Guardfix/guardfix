// What a free GuardFix check looks at, all on your machine except one OSV lookup:
// locked dependency versions (OSV.dev advisories), leaked keys, and Supabase tables without RLS.
import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join, relative, sep } from "node:path";

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".next", ".nuxt", ".output", ".vercel", "coverage",
  ".venv", "venv", "__pycache__", ".turbo", ".cache", "vendor", "out", ".svelte-kit"]);
const MAX_FILE = 1_000_000;

export function walk(root, depth = 8) {
  const out = [];
  const visit = (dir, d) => {
    let names;
    try { names = readdirSync(dir); } catch { return; }
    for (const name of names) {
      const full = join(dir, name);
      let st;
      try { st = statSync(full); } catch { continue; }
      if (st.isDirectory()) {
        if (!SKIP_DIRS.has(name) && d < depth) visit(full, d + 1);
      } else if (st.size <= MAX_FILE) {
        out.push(full);
      }
    }
  };
  visit(root, 0);
  return out;
}

// --- lockfiles -> [{ecosystem, name, version, dev, file}] ----------------------------------------

function npmLock(text) {
  const lock = JSON.parse(text);
  const out = [];
  if (lock.packages) {
    for (const [path, p] of Object.entries(lock.packages)) {
      if (!path || !p.version || p.link) continue;
      const name = p.name || path.slice(path.lastIndexOf("node_modules/") + "node_modules/".length);
      out.push({ name, version: p.version, dev: Boolean(p.dev || p.devOptional) });
    }
  } else if (lock.dependencies) {
    const visit = (deps) => {
      for (const [name, p] of Object.entries(deps)) {
        if (p.version) out.push({ name, version: p.version, dev: Boolean(p.dev) });
        if (p.dependencies) visit(p.dependencies);
      }
    };
    visit(lock.dependencies);
  }
  return out;
}

// pnpm v5-v9. Keys can be quoted ("@scope/a@1.0.0") or not, with a leading "/" (v5-v6) and a peer
// suffix "(react@18.2.0)". v6 marks dev packages with `dev: true`; v9 does not, so there a package
// is production when it is reachable from an importer's dependencies/optionalDependencies.
const unq = (s) => s.trim().replace(/^['"]|['"]$/g, "");
const PNPM_KEY = /^ {2}['"]?\/?((?:@[^/@\s'"]+\/)?[^/@\s'"(]+)[@/]([0-9][^(:'"\s]*)[^:]*:/;

function pnpmLock(text) {
  const nodes = new Map();     // name@version -> {name, version, dev|null, deps:Set}
  const roots = [];            // [name@version, isDev]
  let section = null, entry = null, sub = null, importerKind = null, importerDep = null, legacyKind = null;
  const node = (name, version) => {
    const key = `${name}@${version}`;
    if (!nodes.has(key)) nodes.set(key, { name, version, dev: null, deps: new Set() });
    return nodes.get(key);
  };
  const ver = (v) => { v = unq(v).replace(/^\//, ""); if (/^(link|file|workspace):/.test(v)) return null; const m = v.match(/^([0-9][^(\s]*)/); return m ? m[1] : null; };
  for (const raw of text.split("\n")) {
    const line = raw.replace(/\s+$/, "");
    if (!line || line.trimStart().startsWith("#")) continue;
    if (/^\S/.test(line)) {
      section = line.replace(/:.*$/, ""); entry = null; sub = null;
      legacyKind = /^(dependencies|optionalDependencies)$/.test(section) ? "prod" : section === "devDependencies" ? "dev" : null;
      continue;
    }
    const indent = line.match(/^ */)[0].length;
    if (section === "packages" || section === "snapshots") {
      if (indent === 2) {
        const m = line.match(PNPM_KEY);
        entry = m ? node(m[1], m[2]) : null; sub = null;
        continue;
      }
      if (!entry) continue;
      if (indent === 4) {
        const t = line.trim();
        sub = /^(dependencies|optionalDependencies):$/.test(t) ? "deps" : null;
        if (/^dev: true$/.test(t)) entry.dev = true;
        else if (/^dev: false$/.test(t)) entry.dev = false;
        continue;
      }
      if (indent === 6 && sub === "deps") {
        const m = line.trim().match(/^(['"]?[^:]+?['"]?):\s*(.+)$/);
        const v = m && ver(m[2]);
        if (v) entry.deps.add(`${unq(m[1])}@${v}`);
      }
    } else if (section === "importers") {
      if (indent === 2) { importerKind = null; continue; }
      if (indent === 4) {
        const t = line.trim().replace(/:$/, "");
        importerKind = /^(dependencies|optionalDependencies)$/.test(t) ? "prod" : t === "devDependencies" ? "dev" : null;
        continue;
      }
      if (!importerKind) continue;
      if (indent === 6) {
        const m = line.trim().match(/^(['"]?[^:]+?['"]?):\s*(.*)$/);
        importerDep = m ? unq(m[1]) : null;
        const v = m && m[2] && ver(m[2]);  // pnpm v5 importers: "name: 1.2.3"
        if (v) roots.push([`${importerDep}@${v}`, importerKind === "dev"]);
        continue;
      }
      if (indent === 8 && importerDep) {
        const m = line.trim().match(/^version:\s*(.+)$/);
        const v = m && ver(m[1]);
        if (v) roots.push([`${importerDep}@${v}`, importerKind === "dev"]);
      }
    } else if (legacyKind) {  // single-project v5/v6: top-level dependencies / devDependencies
      if (indent === 2) {
        const m = line.trim().match(/^(['"]?[^:]+?['"]?):\s*(.*)$/);
        importerDep = m ? unq(m[1]) : null;
        const v = m && m[2] && ver(m[2]);
        if (v) roots.push([`${importerDep}@${v}`, legacyKind === "dev"]);
      } else if (indent === 4 && importerDep) {
        const m = line.trim().match(/^version:\s*(.+)$/);
        const v = m && ver(m[1]);
        if (v) roots.push([`${importerDep}@${v}`, legacyKind === "dev"]);
      }
    }
  }
  const all = [...nodes.values()];
  const explicit = all.some((n) => n.dev !== null);
  const prodRoots = roots.filter(([, dev]) => !dev).map(([k]) => k);
  let prod = null;
  if (!explicit && roots.length) {  // v9: walk the graph from production roots
    prod = new Set();
    const stack = [...prodRoots];
    while (stack.length) {
      const k = stack.pop();
      if (prod.has(k)) continue;
      prod.add(k);
      for (const d of nodes.get(k)?.deps || []) stack.push(d);
    }
  }
  return all.map((n) => ({ name: n.name, version: n.version,
    dev: explicit ? n.dev === true : prod ? !prod.has(`${n.name}@${n.version}`) : false }));
}

function yarnLock(text) {
  const out = [];
  let name = null;
  for (const line of text.split("\n")) {
    if (/^\S.*:\s*$/.test(line) && !line.startsWith("#") && !line.startsWith("__metadata")) {
      const spec = line.replace(/:\s*$/, "").split(",")[0].trim().replace(/^"|"$/g, "");
      const at = spec.lastIndexOf("@");
      name = at > 0 ? spec.slice(0, at) : null;
      continue;
    }
    const v = line.match(/^ {2}version:? "?([^"\s]+)"?/);
    if (name && v) {
      out.push({ name, version: v[1], dev: false });
      name = null;
    }
  }
  return out;
}

function bunLock(text) {
  const out = [];
  const re = /"[^"]+":\s*\[\s*"((?:@[^/"]+\/)?[^@"]+)@([0-9][^"]*)"/g;
  for (const m of text.matchAll(re)) out.push({ name: m[1], version: m[2], dev: false });
  return out;
}

function tomlPackages(text) {
  const out = [];
  for (const block of text.split(/^\[\[package\]\]\s*$/m).slice(1)) {
    const name = block.match(/^name\s*=\s*"([^"]+)"/m);
    const version = block.match(/^version\s*=\s*"([^"]+)"/m);
    const cat = block.match(/^category\s*=\s*"([^"]+)"/m);
    if (name && version) out.push({ name: name[1], version: version[1], dev: cat?.[1] === "dev" });
  }
  return out;
}

function requirements(text) {
  const out = [];
  for (const line of text.split("\n")) {
    const m = line.trim().match(/^([A-Za-z0-9_.\-\[\]]+)\s*==\s*([0-9][^\s;#]*)/);
    if (m) out.push({ name: m[1].replace(/\[.*\]/, ""), version: m[2], dev: false });
  }
  return out;
}

const LOCKFILES = {
  "package-lock.json": ["npm", npmLock], "npm-shrinkwrap.json": ["npm", npmLock], "pnpm-lock.yaml": ["npm", pnpmLock],
  "yarn.lock": ["npm", yarnLock], "bun.lock": ["npm", bunLock], "poetry.lock": ["PyPI", tomlPackages],
  "uv.lock": ["PyPI", tomlPackages], "requirements.txt": ["PyPI", requirements],
};

export function packages(root, files) {
  const seen = new Map();
  const used = [];
  for (const file of files) {
    const base = file.slice(file.lastIndexOf(sep) + 1);
    if (!LOCKFILES[base]) continue;
    const [ecosystem, parse] = LOCKFILES[base];
    let list;
    try { list = parse(readFileSync(file, "utf8")); } catch { continue; }
    used.push(relative(root, file));
    for (const p of list) {
      const key = `${ecosystem}|${p.name}|${p.version}`;
      const prev = seen.get(key);
      if (prev) prev.dev = prev.dev && p.dev;  // production anywhere wins
      else seen.set(key, { ecosystem, ...p, file: relative(root, file) });
    }
  }
  return { lockfiles: used, packages: [...seen.values()] };
}

// --- OSV.dev ----------------------------------------------------------------------------------

export function compareVersions(a, b) {
  const pa = String(a).split(/[.\-+]/), pb = String(b).split(/[.\-+]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? "0", y = pb[i] ?? "0";
    const nx = /^\d+$/.test(x), ny = /^\d+$/.test(y);
    if (nx && ny) { if (+x !== +y) return +x - +y; }
    else if (x !== y) return nx ? 1 : ny ? -1 : x < y ? -1 : 1;
  }
  return 0;
}

const LEVEL = { CRITICAL: "critical", HIGH: "high", MODERATE: "medium", MEDIUM: "medium", LOW: "low" };

export function severityOf(vuln) {
  const s = vuln.database_specific?.severity || vuln.affected?.[0]?.database_specific?.severity;
  return LEVEL[String(s || "").toUpperCase()] || "unknown";
}

export function fixedVersion(vuln, pkg) {
  const fixes = [];
  for (const a of vuln.affected || []) {
    if (a.package?.name?.toLowerCase() !== pkg.name.toLowerCase()) continue;
    for (const r of a.ranges || []) for (const e of r.events || []) if (e.fixed) fixes.push(e.fixed);
  }
  return fixes.filter((f) => compareVersions(f, pkg.version) > 0).sort(compareVersions)[0] || null;
}

const TIMEOUT = 20_000;  // a stalled network must not hang the check
const cache = new Map();  // advisory id -> details, shared by the first lookup and the upgrade recheck

export async function advisories(pkgs, { fetch = globalThis.fetch, api = "https://api.osv.dev/v1" } = {}) {
  const out = [];
  const byId = new Map();
  for (let i = 0; i < pkgs.length; i += 500) {
    const chunk = pkgs.slice(i, i + 500);
    const res = await fetch(`${api}/querybatch`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ queries: chunk.map((p) => ({ package: { ecosystem: p.ecosystem, name: p.name }, version: p.version })) }),
      signal: AbortSignal.timeout(TIMEOUT),
    });
    if (!res.ok) throw new Error(`OSV answered ${res.status}`);
    const data = await res.json();
    data.results.forEach((r, j) => { for (const v of r.vulns || []) out.push({ pkg: chunk[j], id: v.id }); });
  }
  const ids = [...new Set(out.map((o) => o.id))];
  const todo = ids.filter((id) => !(cache.has(id) && cache.get(id).api === api && cache.get(id).fetch === fetch));
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(24, todo.length) }, async () => {
    while (next < todo.length) {
      const id = todo[next++];
      const res = await fetch(`${api}/vulns/${encodeURIComponent(id)}`, { signal: AbortSignal.timeout(TIMEOUT) });
      if (res.ok) cache.set(id, { api, fetch, vuln: await res.json() });
    }
  }));
  for (const id of ids) if (cache.has(id)) byId.set(id, cache.get(id).vuln);
  // one finding per package and advisory; a PYSEC entry that has a GHSA twin is dropped
  const findings = [];
  const seen = new Set();
  for (const { pkg, id } of out) {
    const v = byId.get(id);
    if (!v) continue;
    if (!id.startsWith("GHSA") && (v.aliases || []).some((a) => a.startsWith("GHSA") && out.some((o) => o.id === a && o.pkg === pkg))) continue;
    const key = `${pkg.ecosystem}|${pkg.name}|${pkg.version}|${[id, ...(v.aliases || [])].sort()[0]}`;
    if (seen.has(key)) continue;
    seen.add(key);
    findings.push({ kind: "dependency", id, severity: severityOf(v), title: v.summary || id, package: pkg.name,
      version: pkg.version, fixed: fixedVersion(v, pkg), dev: pkg.dev, file: pkg.file, ecosystem: pkg.ecosystem });
  }
  return findings;
}

// The smallest fix of each advisory can still be hit by another advisory (lodash 4.18.0 fixes one
// and is affected by the next). Check the proposed version itself, move up, up to `rounds` times.
// Sets `upgrade` on every finding of a package: the version OSV knows no fixable advisory for.
export async function safeUpgrades(findings, { fetch = globalThis.fetch, api, rounds = 3 } = {}) {
  const groups = new Map();
  for (const f of findings) {
    if (f.kind !== "dependency" || !f.fixed) continue;
    const key = `${f.ecosystem}|${f.package}|${f.version}`;
    const g = groups.get(key) || { pkg: { ecosystem: f.ecosystem, name: f.package, file: f.file }, target: f.fixed, items: [] };
    if (compareVersions(f.fixed, g.target) > 0) g.target = f.fixed;
    g.items.push(f);
    groups.set(key, g);
  }
  let open = [...groups.values()];
  for (let i = 0; i < rounds && open.length; i++) {
    const found = await advisories(open.map((g) => ({ ...g.pkg, version: g.target })), { fetch, ...(api ? { api } : {}) });
    const next = [];
    for (const g of open) {
      const higher = found.filter((x) => x.package === g.pkg.name && x.version === g.target && x.fixed).map((x) => x.fixed);
      if (!higher.length) continue;
      g.target = higher.sort(compareVersions).at(-1);
      next.push(g);
    }
    open = next;
  }
  for (const g of groups.values()) for (const f of g.items) f.upgrade = g.target;
  return findings;
}

// --- leaked keys --------------------------------------------------------------------------------

const TEXT = /\.(js|jsx|ts|tsx|mjs|cjs|vue|svelte|astro|html|json|env|py|toml|yaml|yml|txt|md|sh|rb|go|php)$|(^|[\\/])\.env(\.[\w.-]+)?$/;
const KEYS = [
  ["openai-key", "critical", "OpenAI API key", /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}\b/],
  ["anthropic-key", "critical", "Anthropic API key", /\bsk-ant-[A-Za-z0-9_-]{32,}\b/],
  ["stripe-live", "critical", "Stripe live secret key", /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b/],
  ["aws-key", "critical", "AWS access key", /\bAKIA[0-9A-Z]{16}\b/],
  ["github-token", "critical", "GitHub token", /\b(?:ghp|gho|ghs|ghu)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{50,}\b/],
  ["google-key", "high", "Google API key", /\bAIza[0-9A-Za-z_-]{35}\b/],
  ["private-key", "critical", "Private key", /-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----/],
];
// A real private key has a base64 body right after the header; validators and docs only mention the header.
const KEY_BODY = /-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----(?:\\n|\\r|\s|["'`+,])*[A-Za-z0-9+/]{60,}/;
const TESTS = /(^|[\\/])(tests?|__tests__|spec|fixtures?|testdata|examples?)[\\/]|\.(test|spec)\.[jt]sx?$|(^|[\\/])test_[^\\/]*\.py$|_test\.(py|go)$/;
const JWT = /\beyJ[A-Za-z0-9_-]{10,}\.(eyJ[A-Za-z0-9_-]{10,})\.[A-Za-z0-9_-]{10,}\b/g;

export function mask(value) {
  return value.length <= 10 ? "****" : `${value.slice(0, 6)}…${value.slice(-4)}`;
}

function clientSide(path) {
  return /(^|[\\/])(src|app|pages|components|public|static|client|frontend|web)[\\/]/.test(path) && !/(^|[\\/])(server|api|functions|supabase[\\/]functions)[\\/]/.test(path);
}

const ENV_FILE = /(^|[\\/])\.env(\.[\w.-]+)?$/;

// A key in a local .env that git ignores is where it belongs: it never reaches the repository.
export function gitIgnored(root, files) {
  const env = files.map((f) => relative(root, f)).filter((rel) => ENV_FILE.test(rel));
  if (!env.length) return new Set();
  const r = spawnSync("git", ["-C", root, "check-ignore", "--stdin"], { input: env.join("\n"), encoding: "utf8" });
  return r.status === 0 ? new Set(r.stdout.split("\n").filter(Boolean).map((x) => x.split("/").join(sep))) : new Set();
}

// Whether a file at this project-relative path is looked at for keys at all.
export function keyFile(rel) {
  return TEXT.test(rel) && !/(^|[\\/])\.env\.(example|sample|template)$/.test(rel) && !/lock(\.json|\.yaml)?$|\.lock$/.test(rel);
}

export function isEnvFile(rel) {
  return ENV_FILE.test(rel);
}

// Keys in one file's text; rel is the project-relative path (it decides test files and client code).
export function secretsInText(rel, text) {
  const out = [];
  const lines = text.split("\n");
  lines.forEach((line, i) => {
    for (const [rule, severity, title, re] of KEYS) {
      const m = line.match(re);
      if (m && rule === "private-key" && (TESTS.test(rel) || !KEY_BODY.test(lines.slice(i, i + 3).join("\n")))) continue;
      if (m && out.some((f) => f.id === rule)) continue;
      if (m) out.push({ kind: "secret", id: rule, severity, title: `${title} in the code`, file: rel, line: i + 1, value: mask(m[0]) });
    }
    for (const m of line.matchAll(JWT)) {
      let role = "";
      try { role = JSON.parse(Buffer.from(m[1], "base64url").toString()).role; } catch { continue; }
      if (role === "service_role") {
        out.push({ kind: "secret", id: "supabase-service-role", severity: "critical",
          title: clientSide(rel) ? "Supabase service_role key in client code: anyone can read and change all data"
            : "Supabase service_role key in the code", file: rel, line: i + 1, value: mask(m[0]) });
      }
    }
  });
  return out;
}

export function secrets(root, files, ignored = gitIgnored(root, files)) {
  const out = [];
  for (const file of files) {
    const rel = relative(root, file);
    if (!keyFile(rel) || ignored.has(rel)) continue;
    let text;
    try { text = readFileSync(file, "utf8"); } catch { continue; }
    out.push(...secretsInText(rel, text));
  }
  return out;
}

// --- Supabase tables without row level security -------------------------------------------------

// Statements are read in order: a table dropped later is gone, RLS can be enabled in a later migration.
// Only the public schema is served by the Supabase API; other schemas are not reachable with the anon key.
const SQL_STMT = /create\s+table\s+(?:if\s+not\s+exists\s+)?((?:"?\w+"?\.)?"?\w+"?)|alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?((?:"?\w+"?\.)?"?\w+"?)\s+enable\s+row\s+level\s+security|drop\s+table\s+(?:if\s+exists\s+)?((?:"?\w+"?\.)?"?\w+"?)/gi;

// The column that ties a row to a Supabase user, so an owner-only policy is not a guess: one that references
// auth.users first, then the usual names. null when there is none (the policy then needs a human decision).
const OWNER_NAMES = ["user_id", "owner_id", "owner", "created_by", "author_id", "profile_id", "account_id"];

export function ownerColumn(createSql) {
  const body = createSql.slice(createSql.indexOf("(") + 1, createSql.lastIndexOf(")"));  // the column list only
  const cols = body.split(/,(?![^(]*\))/).map((c) => c.trim()).filter((c) => /^"?\w+"?\s+\w/.test(c) && !/^(constraint|primary|foreign|unique|check)\b/i.test(c));
  const ref = cols.find((c) => /references\s+auth\.users/i.test(c));
  if (ref) return ref.match(/^"?(\w+)"?/)[1].toLowerCase();
  const fk = body.match(/foreign\s+key\s*\(\s*"?(\w+)"?\s*\)\s*references\s+auth\.users/i);
  if (fk) return fk[1].toLowerCase();
  const names = cols.map((c) => c.match(/^"?(\w+)"?/)[1].toLowerCase());
  return OWNER_NAMES.find((n) => names.includes(n)) || null;
}

export function isMigration(rel) {
  return /(^|[\\/])supabase[\\/]migrations[\\/].+\.sql$/.test(rel);
}

// read(file) gives a migration's text: the hook passes the file as it will be after the AI's edit.
export function supabaseRls(root, files, read = (f) => readFileSync(f, "utf8")) {
  const sql = files.filter((f) => isMigration(relative(root, f))).sort();
  if (!sql.length) return [];
  const tables = new Map();
  const rls = new Set();
  const ident = (s) => { const n = s.replace(/"/g, "").toLowerCase(); return n.includes(".") && !n.startsWith("public.") ? null : n.replace(/^public\./, ""); };
  for (const file of sql) {
    let text;
    try { text = read(file).replace(/--[^\n]*/g, ""); } catch { continue; }
    for (const m of text.matchAll(SQL_STMT)) {
      const name = ident(m[1] || m[2] || m[3]);
      if (!name) continue;
      if (m[1]) { tables.set(name, { file: relative(root, file), owner: ownerColumn(text.slice(m.index, text.indexOf(";", m.index) + 1 || undefined)) }); rls.delete(name); }
      else if (m[2]) rls.add(name);
      else { tables.delete(name); rls.delete(name); }
    }
  }
  return [...tables].filter(([t]) => !rls.has(t)).map(([table, { file, owner }]) => ({
    kind: "supabase", id: "supabase-no-rls", severity: "critical", table, file, owner,
    title: `Supabase table "${table}" has no row level security: anyone with the public anon key can read it`,
  }));
}

export function hasProject(root) {
  return existsSync(root) && statSync(root).isDirectory();
}
