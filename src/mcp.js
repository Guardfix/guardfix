// npx guardfix mcp: the same checks as the CLI, as an MCP server over stdio (Claude Code, Codex, Cursor, ...).
// No dependencies: JSON-RPC 2.0, one message per line. stdout carries only protocol messages.
import { resolve } from "node:path";
import { check, prompt, text, byPackage, VERSION } from "./cli.js";
import { advisories, safeUpgrades, hasProject } from "./scan.js";

const PROTOCOLS = ["2025-06-18", "2025-03-26", "2024-11-05"];

const path = { type: "string", description: "Project folder. Defaults to the folder the server was started in." };
export const TOOLS = [
  {
    name: "scan",
    title: "GuardFix scan",
    description: "Security check of a project: vulnerable dependencies (OSV.dev, with the lowest version that has no known fixable advisory), leaked API keys in code, Supabase tables without row level security. Returns a grade A+..F and every finding. Only package names and versions leave the machine.",
    inputSchema: { type: "object", properties: { path, offline: { type: "boolean", description: "Skip the OSV.dev lookup: keys and RLS only." } } },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  {
    name: "check_package",
    title: "Is this package version safe?",
    description: "Look up one package version in OSV.dev before adding or pinning it. Returns its known advisories and the lowest version with no known fixable advisory. Call it before writing a dependency version into package.json, requirements.txt or pyproject.toml.",
    inputSchema: {
      type: "object", required: ["name", "version"],
      properties: {
        name: { type: "string", description: "Package name, e.g. axios or @supabase/supabase-js" },
        version: { type: "string", description: "Exact version, e.g. 1.6.0" },
        ecosystem: { type: "string", enum: ["npm", "PyPI"], default: "npm" },
      },
    },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  {
    name: "fix_plan",
    title: "GuardFix fix plan",
    description: "Scan the project and return step-by-step fix instructions with exact versions and the Supabase policies to add. Follow them, then call scan again to confirm.",
    inputSchema: { type: "object", properties: { path } },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
];

function folder(args, cwd) {
  const root = resolve(cwd, typeof args.path === "string" && args.path ? args.path : ".");
  if (!hasProject(root)) throw new Error(`No such folder: ${root}`);
  return root;
}

export async function checkPackage({ name, version, ecosystem = "npm" }, { fetch = globalThis.fetch } = {}) {
  if (typeof name !== "string" || !name || typeof version !== "string" || !version) throw new Error("name and version are required");
  if (!["npm", "PyPI"].includes(ecosystem)) throw new Error("ecosystem must be npm or PyPI");
  const found = await advisories([{ ecosystem, name, version, file: "" }], { fetch });
  await safeUpgrades(found, { fetch });
  const [group] = byPackage(found);
  return {
    package: name, version, ecosystem, safe: found.length === 0,
    worst: group?.severity ?? null,
    upgrade: group?.fixed ?? null,
    advisories: found.map((f) => ({ id: f.id, severity: f.severity, title: f.title, fixed: f.fixed })),
  };
}

function describe(p) {
  if (p.safe) return `${p.package} ${p.version} (${p.ecosystem}): OSV.dev knows no advisories for this version.`;
  const lines = [`${p.package} ${p.version} (${p.ecosystem}): ${p.advisories.length} known advisories, worst ${p.worst}.`,
    p.upgrade ? `Use ${p.upgrade} or later: the lowest version with no known fixable advisory.` : "No fixed version is published yet."];
  for (const a of p.advisories.slice(0, 15)) lines.push(`- ${a.id} [${a.severity}] ${a.title}`);
  if (p.advisories.length > 15) lines.push(`- … ${p.advisories.length - 15} more`);
  return lines.join("\n");
}

export async function callTool(name, args = {}, { fetch = globalThis.fetch, cwd = process.env.CLAUDE_PROJECT_DIR || process.cwd() } = {}) {
  if (name === "check_package") {
    const p = await checkPackage(args, { fetch });
    return { content: [{ type: "text", text: describe(p) }], structuredContent: p };
  }
  if (name === "scan" || name === "fix_plan") {
    const r = await check(folder(args, cwd), { fetch, offline: name === "scan" && args.offline === true });
    const out = name === "scan" ? text(r).trim() : prompt(r);
    return { content: [{ type: "text", text: out }],
      structuredContent: { project: r.project, grade: r.grade, complete: r.complete, findings: r.findings.length, packages: byPackage(r.findings).length } };
  }
  throw Object.assign(new Error(`Unknown tool: ${name}`), { code: -32602 });
}

export async function handle(msg, ctx = {}) {
  const { id, method, params = {} } = msg || {};
  const reply = (result) => ({ jsonrpc: "2.0", id, result });
  const fail = (code, message) => ({ jsonrpc: "2.0", id: id ?? null, error: { code, message } });
  if (!msg || msg.jsonrpc !== "2.0" || typeof method !== "string") return id === undefined ? null : fail(-32600, "Invalid request");
  if (id === undefined) return null;  // notifications (initialized, cancelled) need no answer
  if (method === "initialize") {
    const protocolVersion = PROTOCOLS.includes(params.protocolVersion) ? params.protocolVersion : PROTOCOLS[0];
    return reply({ protocolVersion, capabilities: { tools: {} }, serverInfo: { name: "guardfix", version: VERSION },
      instructions: "Call check_package before adding or pinning a dependency version. Call scan to grade the project; fix_plan for exact fix steps." });
  }
  if (method === "ping") return reply({});
  if (method === "tools/list") return reply({ tools: TOOLS });
  if (method === "tools/call") {
    try { return reply(await callTool(params.name, params.arguments, ctx)); } catch (e) {
      if (e.code === -32602) return fail(-32602, e.message);
      return reply({ content: [{ type: "text", text: `guardfix: ${e.message || e}` }], isError: true });
    }
  }
  return fail(-32601, `Method not found: ${method}`);
}

export function serve({ input = process.stdin, output = process.stdout, ...ctx } = {}) {
  let buffer = "";
  const send = (m) => { if (m) output.write(JSON.stringify(m) + "\n"); };
  input.setEncoding("utf8");
  input.on("data", (chunk) => {
    buffer += chunk;
    let nl;
    while ((nl = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, nl).trim();
      buffer = buffer.slice(nl + 1);
      if (!line) continue;
      let msg;
      try { msg = JSON.parse(line); } catch { send({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }); continue; }
      handle(msg, ctx).then(send, (e) => send({ jsonrpc: "2.0", id: msg.id ?? null, error: { code: -32603, message: String(e.message || e) } }));
    }
  });
  return new Promise((done) => input.on("end", done));
}
