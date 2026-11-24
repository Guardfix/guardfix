// The guard: Claude Code asks it before the AI writes a file (PreToolUse on Write, Edit, MultiEdit).
// It looks only at what this edit adds: a key written into the code, a Supabase table created without row level
// security, a dependency pinned to a version with a known high or critical vulnerability. Anything already in the
// file is the job of `npx guardfix`. On any doubt or error it lets the edit through: it must never get in the way.
import { readFileSync, existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { relative, resolve, isAbsolute } from "node:path";
import { walk, secretsInText, keyFile, isEnvFile, gitIgnored, supabaseRls, isMigration, advisories, safeUpgrades,
  compareVersions } from "./scan.js";

const EXACT = /^=?\s*v?(\d+\.\d+\.\d+(?:[-+][\w.+-]+)?)$/;
const ORDER = { critical: 0, high: 1 };

function replace(text, oldString, newString, all) {
  if (typeof oldString !== "string" || typeof newString !== "string" || !oldString || !text.includes(oldString)) return null;
  return all ? text.split(oldString).join(newString) : text.replace(oldString, () => newString);
}

// The file as it will be after the tool runs; null when we cannot tell (the tool will then fail on its own).
export function afterEdit(tool, input, before) {
  if (tool === "Write") return typeof input.content === "string" ? input.content : null;
  if (tool === "Edit") return replace(before, input.old_string, input.new_string, input.replace_all);
  if (tool === "MultiEdit" && Array.isArray(input.edits)) {
    let text = before;
    for (const e of input.edits) {
      text = replace(text, e?.old_string, e?.new_string, e?.replace_all);
      if (text === null) return null;
    }
    return text;
  }
  return null;
}

// Exact production pins only: a range is resolved at install time, and the session-start check sees the lock.
export function pins(rel, text) {
  const out = new Map();
  const name = rel.split(/[\\/]/).pop();
  if (name === "package.json") {
    let doc;
    try { doc = JSON.parse(text); } catch { return out; }
    for (const [pkg, spec] of Object.entries(doc?.dependencies || {})) {
      const m = typeof spec === "string" && spec.trim().match(EXACT);
      if (m) out.set(`npm|${pkg}`, { ecosystem: "npm", name: pkg, version: m[1] });
    }
  } else if (/^requirements[\w.-]*\.txt$/.test(name)) {
    for (const line of text.split("\n")) {
      const m = line.trim().match(/^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*==\s*([0-9][^\s;#]*)/);
      if (m) out.set(`PyPI|${m[1].toLowerCase()}`, { ecosystem: "PyPI", name: m[1], version: m[2] });
    }
  }
  return out;
}

function inGitRepo(root) {
  return spawnSync("git", ["-C", root, "rev-parse", "--is-inside-work-tree"], { encoding: "utf8" }).status === 0;
}

function keyProblems(root, file, rel, before, after) {
  if (!keyFile(rel)) return [];
  // A real key in a local .env is where it belongs, as long as git ignores that file.
  if (isEnvFile(rel) && (!inGitRepo(root) || gitIgnored(root, [file]).has(rel))) return [];
  const had = new Set(secretsInText(rel, before).map((f) => `${f.id}|${f.value}`));
  return secretsInText(rel, after).filter((f) => !had.has(`${f.id}|${f.value}`)).map((f) => {
    const what = f.title.replace(/ in the code$/, "").replace(/: .*$/, "");
    const role = f.id === "supabase-service-role"
      ? " The service_role key bypasses all row level security: never put it in code that runs in the browser; the client uses the anon key."
      : "";
    const env = isEnvFile(rel)
      ? ` ${rel} is not ignored by git, so the key would be committed: add ${rel} to .gitignore first.`
      : " Read it from an environment variable on the server side instead, keep the real value in a git-ignored .env, and list the variable name in .env.example.";
    return `${what} written into ${rel}:${f.line} (${f.value}).${role}${env}`;
  });
}

function rlsProblems(root, file, rel, after) {
  if (!isMigration(rel)) return [];
  const files = walk(root).filter((f) => isMigration(relative(root, f)));
  const withFile = files.includes(file) ? files : [...files, file];
  const known = new Set(supabaseRls(root, files).map((f) => f.table));
  const read = (f) => (f === file ? after : readFileSync(f, "utf8"));
  return supabaseRls(root, withFile, read).filter((f) => !known.has(f.table) && f.file === rel).map((f) =>
    `The migration ${rel} creates the table "${f.table}" in the public schema without row level security: anyone ` +
    `with the public anon key could read it. Add \`alter table public.${f.table} enable row level security;\` to this ` +
    "migration, with policies: " + (f.owner
      ? `owner-only, using (auth.uid() = ${f.owner}) for select, update and delete and with check (auth.uid() = ${f.owner}) for insert.`
      : "ask the user who may read and write this table, the table has no column tying a row to a user."));
}

async function dependencyProblems(rel, before, after, fetch) {
  const old = pins(rel, before);
  const added = [...pins(rel, after)].filter(([k, p]) => old.get(k)?.version !== p.version).map(([, p]) => ({ ...p, file: rel, dev: false }));
  if (!added.length) return [];
  const found = (await advisories(added, { fetch })).filter((f) => f.fixed && f.severity in ORDER);
  if (!found.length) return [];
  await safeUpgrades(found, { fetch });
  const groups = new Map();
  for (const f of found) {
    const g = groups.get(f.package) || { ...f, ids: [], to: null };
    g.ids.push(f.id);
    if (ORDER[f.severity] < ORDER[g.severity]) g.severity = f.severity;
    const to = f.upgrade || f.fixed;
    if (!g.to || compareVersions(to, g.to) > 0) g.to = to;
    groups.set(f.package, g);
  }
  return [...groups.values()].map((g) => `${g.package} ${g.version} in ${rel} has ${g.ids.length} known ` +
    `vulnerabilit${g.ids.length === 1 ? "y" : "ies"}, worst ${g.severity} (${g.ids.slice(0, 3).join(", ")}${g.ids.length > 3 ? ", …" : ""}): ` +
    `use ${g.to} or newer.`);
}

// { problems: [...], kinds: Set } for one tool call; never throws.
export async function review({ root, tool, input, fetch = globalThis.fetch, offline = false }) {
  const none = { problems: [], kinds: new Set() };
  try {
    if (!input || typeof input.file_path !== "string") return none;
    const file = isAbsolute(input.file_path) ? input.file_path : resolve(root, input.file_path);
    const rel = relative(root, file);
    if (!rel || rel.startsWith("..") || isAbsolute(rel)) return none;  // outside the project
    const before = existsSync(file) ? readFileSync(file, "utf8") : "";
    const after = afterEdit(tool, input, before);
    if (after === null || after === before) return none;
    const keys = keyProblems(root, file, rel, before, after);
    const rls = rlsProblems(root, file, rel, after);
    let deps = [];
    if (!offline) {
      try { deps = await dependencyProblems(rel, before, after, fetch); } catch { deps = []; }
    }
    const kinds = new Set([...(keys.length ? ["key"] : []), ...(rls.length ? ["rls"] : []), ...(deps.length ? ["dependency"] : [])]);
    return { problems: [...keys, ...rls, ...deps], kinds, rel };
  } catch {
    return none;
  }
}

const LABEL = { key: "a leaked key", rls: "a table without RLS", dependency: "a vulnerable version" };

// The PreToolUse answer: deny with what to change, or nothing.
export function decision(result) {
  if (!result.problems.length) return null;
  const what = [...result.kinds].map((k) => LABEL[k]).join(", ");
  return {
    systemMessage: `GuardFix stopped ${what} in ${result.rel}`,
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: "GuardFix blocked this edit:\n" + result.problems.map((p) => `- ${p}`).join("\n") +
        "\nChange the edit and try again. Tell the user in one line what GuardFix caught and how you fixed it.",
    },
  };
}
