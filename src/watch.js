// The watch: Claude Code runs it when a session starts (SessionStart). It looks the project's locked dependency
// versions up in OSV.dev and says what is new since the last time: an advisory published for a package you use,
// or a vulnerable version that came in with an install. Only package names and versions leave the machine, as with
// `npx guardfix`. The state lives in ~/.guardfix/watch, outside the project. Quiet when nothing changed.
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { walk, packages, advisories, safeUpgrades, compareVersions } from "./scan.js";

export const EVERY = 6 * 3600_000;  // the same locks are looked up again after 6 hours
const ORDER = { critical: 0, high: 1 };

export function stateFile(root, home = process.env.GUARDFIX_HOME || join(homedir(), ".guardfix")) {
  return join(home, "watch", createHash("sha256").update(resolve(root)).digest("hex").slice(0, 32) + ".json");
}

function groups(findings) {
  const out = new Map();
  for (const f of findings) {
    const key = `${f.package}@${f.version}`;
    const g = out.get(key) || { package: f.package, version: f.version, severity: f.severity, to: null, count: 0 };
    g.count += 1;
    if (ORDER[f.severity] < ORDER[g.severity]) g.severity = f.severity;
    const to = f.upgrade || f.fixed;
    if (to && (!g.to || compareVersions(to, g.to) > 0)) g.to = to;
    out.set(key, g);
  }
  return [...out.values()].sort((a, b) => ORDER[a.severity] - ORDER[b.severity] || b.count - a.count);
}

function list(gs) {
  const shown = gs.slice(0, 5).map((g) => `${g.package} ${g.version} (${g.severity}) → ${g.to}`);
  return shown.join(", ") + (gs.length > 5 ? `, and ${gs.length - 5} more` : "");
}

// { message (for the user), context (for the AI) } or null when there is nothing to say.
export async function watch(root, { fetch = globalThis.fetch, now = Date.now(), home } = {}) {
  const files = walk(root);
  const { lockfiles, packages: pkgs } = packages(root, files);
  if (!lockfiles.length || !pkgs.length) return null;
  const hash = createHash("sha256");
  for (const rel of lockfiles.sort()) hash.update(rel + "\0" + readFileSync(join(root, rel)));
  const lockHash = hash.digest("hex");
  const path = stateFile(root, home);
  let state = null;
  try { state = JSON.parse(readFileSync(path, "utf8")); } catch { state = null; }
  if (state && state.lockHash === lockHash && now - state.checked < EVERY) return null;

  let found;
  try {
    found = (await advisories(pkgs, { fetch })).filter((f) => !f.dev && f.fixed && f.severity in ORDER);
    await safeUpgrades(found, { fetch });
  } catch {
    return null;  // offline or OSV unreachable: say nothing, try again next session
  }
  const keys = [...new Set(found.map((f) => `${f.package}@${f.version}|${f.id}`))];
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(path, JSON.stringify({ checked: now, lockHash, known: keys }));

  if (!state) {
    if (!found.length) {
      return { message: "GuardFix is watching this project: no known high or critical vulnerability in its dependencies.",
        context: "" };
    }
    const gs = groups(found);
    return {
      message: `GuardFix is watching this project: ${gs.length} vulnerable package${gs.length === 1 ? "" : "s"} with a fix (${list(gs)}). Run /guardfix fix`,
      context: `GuardFix found ${gs.length} ${gs.length === 1 ? "dependency" : "dependencies"} of this project with known high or critical vulnerabilities that ` +
        `have a fix: ${list(gs)}. Mention this to the user once, in their language, and offer to run /guardfix fix.`,
    };
  }
  const known = new Set(state.known || []);
  const fresh = found.filter((f) => !known.has(`${f.package}@${f.version}|${f.id}`));
  if (!fresh.length) return null;
  const gs = groups(fresh);
  const since = new Date(state.checked).toISOString().slice(0, 10);
  return {
    message: `GuardFix: new since ${since} — ${list(gs)}. Run /guardfix fix`,
    context: `Since ${since}, ${fresh.length} new high or critical vulnerabilit${fresh.length === 1 ? "y was" : "ies were"} found in this ` +
      `project's dependencies: ${list(gs)}. Tell the user at the start of your next reply, in their language, and offer to run /guardfix fix.`,
  };
}
