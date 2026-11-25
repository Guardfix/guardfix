// npx guardfix [path] [--json] [--prompt] [--card] [--offline]
import { readFileSync, writeFileSync } from "node:fs";
import { resolve, join, basename } from "node:path";
import { walk, packages, advisories, safeUpgrades, secrets, supabaseRls, hasProject, compareVersions } from "./scan.js";

export const VERSION = "0.2.0";
const ORDER = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
// Vibe Security Index, November 2026: AI-built public projects (production dependencies, high/critical with a fix)
export const INDEX = { share: 74, median: 15, projects: 1256 };

export function byPackage(findings) {
  const groups = new Map();
  for (const f of findings.filter((x) => x.kind === "dependency")) {
    const key = `${f.package}@${f.version}`;
    const g = groups.get(key) || { package: f.package, version: f.version, file: f.file, severity: "unknown", fixed: null, count: 0, ids: [] };
    g.count += 1;
    g.ids.push(f.id);
    if (ORDER[f.severity] < ORDER[g.severity]) g.severity = f.severity;
    const to = f.upgrade || f.fixed;
    if (to && (!g.fixed || compareVersions(to, g.fixed) > 0)) g.fixed = to;
    if (!f.fixed) g.unfixed = (g.unfixed || 0) + 1;
    groups.set(key, g);
  }
  return [...groups.values()].sort((a, b) => ORDER[a.severity] - ORDER[b.severity] || b.count - a.count);
}

export function grade(findings) {
  const s = findings.map((f) => f.severity);
  if (s.includes("critical")) return "F";
  if (s.includes("high")) return "D";
  const medium = s.filter((x) => x === "medium").length;
  return medium >= 3 ? "C" : medium ? "B" : s.length ? "A" : "A+";
}

export async function check(root, { fetch, offline = false } = {}) {
  const files = walk(root);
  const { lockfiles, packages: pkgs } = packages(root, files);
  let deps = [];
  let osvError = null;
  if (!offline && pkgs.length) {
    try {
      deps = await advisories(pkgs, { fetch });
      await safeUpgrades(deps.filter((f) => !f.dev), { fetch });
    } catch (e) { osvError = String(e.message || e); }
  }
  const prod = deps.filter((f) => !f.dev);
  const graded = [...prod, ...secrets(root, files), ...supabaseRls(root, files)]
    .sort((a, b) => ORDER[a.severity] - ORDER[b.severity]);
  const indexComparable = prod.filter((f) => f.fixed && (f.severity === "high" || f.severity === "critical"));
  // A grade without the dependency lookup would look clean when it is not: no card or badge then.
  const complete = !(lockfiles.length && (offline || osvError));
  return {
    project: basename(root), grade: grade(graded), complete, findings: graded, dev: deps.filter((f) => f.dev),
    lockfiles, packages: pkgs.length, osvError, offline,
    index: { yours: new Set(indexComparable.map((f) => `${f.package}@${f.version}|${f.id}`)).size, ...INDEX },
  };
}

const C = process.stdout.isTTY && !process.env.NO_COLOR
  ? { r: "\x1b[31m", y: "\x1b[33m", g: "\x1b[32m", d: "\x1b[2m", b: "\x1b[1m", x: "\x1b[0m" }
  : { r: "", y: "", g: "", d: "", b: "", x: "" };
const SEV = { critical: `${C.r}CRITICAL${C.x}`, high: `${C.r}HIGH${C.x}`, medium: `${C.y}MEDIUM${C.x}`, low: `${C.d}LOW${C.x}`, unknown: `${C.d}?${C.x}` };

function where(f) {
  if (f.kind === "dependency") return `${f.package}@${f.version}${f.fixed ? ` → ${C.g}${f.fixed}${C.x}` : " (no fix yet)"}`;
  if (f.kind === "secret") return `${f.file}:${f.line}  ${C.d}${f.value}${C.x}`;
  return f.file;
}

export function text(r) {
  const color = r.grade.startsWith("A") ? C.g : r.grade === "B" || r.grade === "C" ? C.y : C.r;
  const lines = [``, `  ${C.b}GuardFix${C.x} · ${r.project}`, ``,
    `  Grade  ${C.b}${color}${r.grade}${C.x}${r.complete ? "" : `  ${C.y}(incomplete: dependencies were not checked)${C.x}`}`, ``];
  const counts = Object.keys(ORDER).map((k) => [k, r.findings.filter((f) => f.severity === k).length]).filter(([, n]) => n);
  lines.push(`  ${counts.length ? counts.map(([k, n]) => `${n} ${k}`).join(" · ") : "no problems found"}` +
    `${C.d}  (${r.packages} packages in ${r.lockfiles.length} lockfile(s); dev-only: ${r.dev.length} more)${C.x}`);
  if (r.osvError) lines.push(`  ${C.y}Dependency check skipped: ${r.osvError}${C.x}`);
  if (r.offline) lines.push(`  ${C.y}Offline: dependencies were not checked${C.x}`);
  lines.push("");
  const other = r.findings.filter((f) => f.kind !== "dependency");
  for (const f of other) lines.push(`  ${SEV[f.severity].padEnd(18)} ${f.title.length > 110 ? f.title.slice(0, 109) + "…" : f.title}`, `  ${" ".repeat(9)}${C.d}${where(f)}${C.x}`);
  const groups = byPackage(r.findings);
  if (groups.length) lines.push(...(other.length ? [""] : []), `  ${C.b}Vulnerable dependencies${C.x} ${C.d}(${groups.length} packages, ${r.findings.length - other.length} advisories)${C.x}`);
  for (const g of groups.slice(0, 15)) {
    const fix = g.fixed ? `→ ${C.g}${g.fixed}${C.x}` : `${C.d}no fix yet${C.x}`;
    lines.push(`  ${SEV[g.severity].padEnd(18)} ${g.package} ${g.version} ${fix}  ${C.d}${g.count} advisor${g.count > 1 ? "ies" : "y"}${g.unfixed ? `, ${g.unfixed} without a fix` : ""}${C.x}`);
  }
  if (groups.length > 15) lines.push(`  ${C.d}…and ${groups.length - 15} more packages (--json for all)${C.x}`);
  if (!r.offline && !r.osvError && r.lockfiles.length) {
    lines.push("", `  ${C.b}Compared with ${r.index.projects} AI-built apps${C.x} (Vibe Security Index): ${r.index.share}% ship a known` +
      ` high/critical vulnerability with a fix, median ${r.index.median}. ${r.index.yours ? `You have ${C.b}${r.index.yours}${C.x}.` : `${C.g}You have none.${C.x}`}`);
  }
  lines.push("", `  ${C.b}Next:${C.x}`,
    `  · npx guardfix --prompt   a ready prompt to paste into Claude Code / Cursor / Codex`,
    `  · npx guardfix --card     a shareable grade card (guardfix-card.svg) and a README badge`,
    `  · ${C.b}https://guardfix.io/cli/?utm_source=cli${C.x}  the fix done for you and verified (install, rescan, build, tests), as a pull request`, "");
  return lines.join("\n");
}

export function prompt(r) {
  const byPkg = new Map(byPackage(r.findings).filter((g) => g.fixed).map((g) => [g.package, g]));
  const out = ["Fix these security problems found by GuardFix in this project. Keep the change minimal.",
    "Never print the value of a key: do not cat or echo files that contain one; edit them in place.", ""];
  let n = 0;
  if (byPkg.size) {
    out.push(`${++n}. Upgrade these dependencies to at least the version shown. It is the lowest version with no known fixable advisory, so it can be above the first fix of each single advisory. If it is a new major, check the changelog for breaking changes:`);
    for (const g of byPkg.values()) out.push(`   - ${g.package}: ${g.version} -> ${g.fixed}  (worst: ${g.severity}, ${g.count} advisories: ${g.ids.slice(0, 3).join(", ")}${g.ids.length > 3 ? ", …" : ""})`);
    out.push("   If a package is only a transitive dependency, upgrade the direct dependency that pulls it in, or add an override/resolution.",
      `   Regenerate the lockfile with the project's own package manager (${r.lockfiles.join(", ")}), do not edit it by hand.`);
  }
  const keys = r.findings.filter((f) => f.kind === "secret");
  if (keys.length) {
    out.push(`${++n}. Leaked keys:`);
    for (const f of keys) out.push(`   - ${f.title} (${f.file}:${f.line})`);
    out.push("   Read the key from an environment variable instead (server side only; a browser bundle must never get a secret key).",
      "   Add the variable name without its value to .env.example, and make sure .env is in .gitignore.",
      "   Tell me to rotate each key now: it is already exposed, and it stays in the git history even after this change.");
  }
  const tables = r.findings.filter((f) => f.kind === "supabase");
  if (tables.length) {
    out.push(`${++n}. Supabase tables without row level security. Add a new migration (do not edit old ones) that runs \`alter table ... enable row level security;\` and adds policies:`);
    for (const f of tables) out.push(`   - ${f.table} (${f.file}): ${f.owner ? `owner-only policies on \`auth.uid() = ${f.owner}\`` : "no owner column found: ask me who may read and write it before writing a policy"}`);
    out.push("   Do not apply the migration to any database; show it to me first.");
  }
  out.push("", "Then: install from scratch, run the build and the tests, and run `npx guardfix` again. Report what changed and anything that could not be fixed" +
    `${keys.length ? ", and remind me that the leaked keys must be rotated even if the new grade is clean" : ""}.`);
  return out.join("\n");
}

export function card(r, before = null) {
  const color = r.grade.startsWith("A") ? "#1a624b" : r.grade === "B" || r.grade === "C" ? "#b7791f" : "#b42318";
  const n = (k) => r.findings.filter((f) => f.severity === k).length;
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
  const was = before && before !== r.grade
    ? `<text x="111" y="104" font-size="14" text-anchor="middle" fill="#596b5e">was <tspan font-weight="700">${esc(before)}</tspan> → now</text>` : "";
  return `<svg xmlns="http://www.w3.org/2000/svg" width="600" height="314" viewBox="0 0 600 314" data-grade="${r.grade}" font-family="-apple-system,Segoe UI,Helvetica,Arial,sans-serif">
<rect width="600" height="314" rx="24" fill="#c9ddd1"/>
<text x="36" y="56" font-size="15" font-weight="700" fill="#1a624b" letter-spacing="1.4">GUARDFIX SECURITY GRADE</text>
<text x="36" y="80" font-size="20" fill="#173b31">${esc(r.project).slice(0, 34)}</text>
${was}<rect x="36" y="110" width="150" height="150" rx="22" fill="#fffefa"/>
<text x="111" y="218" font-size="${r.grade.length > 1 ? 72 : 96}" text-anchor="middle" font-family="Georgia,serif" fill="${color}">${r.grade}</text>
<text x="216" y="140" font-size="17" fill="#173b31"><tspan font-weight="700">${n("critical")}</tspan> critical · <tspan font-weight="700">${n("high")}</tspan> high · <tspan font-weight="700">${n("medium")}</tspan> medium</text>
<text x="216" y="176" font-size="15" fill="#33493f">Known vulnerable dependencies with a fix: ${r.index.yours}</text>
<text x="216" y="202" font-size="15" fill="#33493f">Typical AI-built app: ${r.index.median} (Vibe Security Index)</text>
<text x="216" y="238" font-size="14" fill="#596b5e">Leaked keys: ${r.findings.filter((f) => f.kind === "secret").length} · Supabase tables without RLS: ${r.findings.filter((f) => f.kind === "supabase").length}</text>
<text x="36" y="292" font-size="14" fill="#1a624b">npx guardfix · guardfix.io</text>
</svg>
`;
}

export function badge(r) {
  const color = r.grade.startsWith("A") ? "brightgreen" : r.grade === "B" ? "yellowgreen" : r.grade === "C" ? "yellow" : "red";
  return `[![GuardFix grade](https://img.shields.io/badge/GuardFix-${encodeURIComponent(r.grade)}-${color})](https://guardfix.io/vibe-security-index/?utm_source=badge)`;
}

export async function main(argv, { fetch, log = console.log } = {}) {
  if (argv[0] === "mcp") { await (await import("./mcp.js")).serve({ fetch }); return 0; }
  if (argv[0] === "install") {
    const { install, report } = await import("./install.js");
    const dryRun = argv.includes("--dry-run");
    log(report(install({ dryRun }), dryRun));
    return 0;
  }
  const flags = new Set(argv.filter((a) => a.startsWith("--")));
  if (flags.has("--help") || flags.has("-h")) {
    log("Usage: npx guardfix [path] [--json] [--prompt] [--card] [--offline]\n       npx guardfix install [--dry-run]   connect GuardFix to Claude Code, Codex, Cursor, VS Code, Claude Desktop\n       npx guardfix mcp   (the MCP server those apps start)\n\nFree security check of a project: vulnerable dependencies (OSV.dev),\nleaked keys, Supabase tables without row level security. Nothing leaves your\nmachine except package names and versions sent to OSV.dev (skip with --offline).");
    return 0;
  }
  if (flags.has("--version")) { log(VERSION); return 0; }
  const root = resolve(argv.find((a) => !a.startsWith("--")) || ".");
  if (!hasProject(root)) { log(`No such folder: ${root}`); return 2; }
  const r = await check(root, { fetch, offline: flags.has("--offline") });
  if (flags.has("--json")) log(JSON.stringify({ ...r, badge: r.complete ? badge(r) : null }, null, 2));
  else if (flags.has("--prompt")) log(prompt(r));
  else log(text(r));
  if (flags.has("--card") && !r.complete) log("No card: the dependencies were not checked, so the grade is incomplete. Run again online.");
  else if (flags.has("--card")) {
    const path = join(root, "guardfix-card.svg");
    let before = null;
    try { before = readFileSync(path, "utf8").match(/data-grade="([A-F+]{1,2})"/)?.[1] || null; } catch { /* first card */ }
    writeFileSync(path, card(r, before));
    log(`Card: ${path}\nBadge for your README:\n${badge(r)}`);
  }
  return r.grade === "F" || r.grade === "D" ? 1 : 0;
}
