// npx guardfix install: connect the GuardFix MCP server to every AI app found on this computer.
// Each config is merged, never replaced: other servers stay, a backup is written first, a file
// that does not parse is left alone. Running it twice changes nothing.
import { existsSync, readFileSync, writeFileSync, mkdirSync, copyFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, dirname } from "node:path";
import { spawnSync } from "node:child_process";

// GUI apps on macOS do not get the shell PATH, so they get the absolute npx next to this node.
export function npxCommand(execPath = process.execPath) {
  const npx = join(dirname(execPath), process.platform === "win32" ? "npx.cmd" : "npx");
  return existsSync(npx) ? npx : "npx";
}

function appData(home, platform, env) {
  if (platform === "darwin") return join(home, "Library", "Application Support");
  if (platform === "win32") return env.APPDATA || join(home, "AppData", "Roaming");
  return env.XDG_CONFIG_HOME || join(home, ".config");
}

export function targets({ home = homedir(), platform = process.platform, env = process.env } = {}) {
  const data = appData(home, platform, env);
  return [
    { app: "Cursor", dir: join(home, ".cursor"), file: join(home, ".cursor", "mcp.json"), key: "mcpServers" },
    { app: "Windsurf", dir: join(home, ".codeium", "windsurf"), file: join(home, ".codeium", "windsurf", "mcp_config.json"), key: "mcpServers" },
    { app: "Claude Desktop", dir: join(data, "Claude"), file: join(data, "Claude", "claude_desktop_config.json"), key: "mcpServers" },
    { app: "VS Code", dir: join(data, "Code", "User"), file: join(data, "Code", "User", "mcp.json"), key: "servers", extra: { type: "stdio" } },
    { app: "Codex", dir: join(home, ".codex"), file: join(home, ".codex", "config.toml"), toml: true },
  ];
}

function backup(file) {
  if (existsSync(file)) copyFileSync(file, `${file}.guardfix-backup`);
}

function installJson(t, command, dryRun) {
  let config = {};
  if (existsSync(t.file)) {
    const raw = readFileSync(t.file, "utf8");
    if (raw.trim()) {
      try { config = JSON.parse(raw); } catch { return { app: t.app, status: "skipped", note: `${t.file} is not valid JSON, left as is` }; }
    }
    if (!config || typeof config !== "object" || Array.isArray(config)) return { app: t.app, status: "skipped", note: `${t.file} has an unexpected shape` };
  }
  if (config[t.key]?.guardfix) return { app: t.app, status: "already", file: t.file };
  config[t.key] = { ...(config[t.key] || {}), guardfix: { ...(t.extra || {}), command, args: ["-y", "guardfix", "mcp"] } };
  if (!dryRun) {
    mkdirSync(dirname(t.file), { recursive: true });
    backup(t.file);
    writeFileSync(t.file, JSON.stringify(config, null, 2) + "\n");
  }
  return { app: t.app, status: "added", file: t.file };
}

function installToml(t, command, dryRun) {
  const raw = existsSync(t.file) ? readFileSync(t.file, "utf8") : "";
  if (/^\s*\[mcp_servers\.guardfix\]/m.test(raw)) return { app: t.app, status: "already", file: t.file };
  const block = `\n[mcp_servers.guardfix]\ncommand = ${JSON.stringify(command)}\nargs = ["-y", "guardfix", "mcp"]\n`;
  if (!dryRun) {
    mkdirSync(dirname(t.file), { recursive: true });
    backup(t.file);
    writeFileSync(t.file, raw.replace(/\s*$/, raw ? "\n" : "") + block);
  }
  return { app: t.app, status: "added", file: t.file };
}

// Claude Code keeps its own config: ask its CLI, which knows where it lives.
function installClaudeCode(run, dryRun) {
  const has = run("claude", ["mcp", "get", "guardfix"]);
  if (has.error?.code === "ENOENT") return null;
  if (has.status === 0) return { app: "Claude Code", status: "already" };
  if (dryRun) return { app: "Claude Code", status: "added" };
  const add = run("claude", ["mcp", "add", "--scope", "user", "guardfix", "--", "npx", "-y", "guardfix", "mcp"]);
  return add.status === 0 ? { app: "Claude Code", status: "added" }
    : { app: "Claude Code", status: "skipped", note: "claude mcp add failed; run: claude mcp add --scope user guardfix -- npx -y guardfix mcp" };
}

const defaultRun = (cmd, args) => spawnSync(cmd, args, { encoding: "utf8", timeout: 20_000, shell: process.platform === "win32" });

export function install({ home, platform, env, dryRun = false, run = defaultRun, command = npxCommand() } = {}) {
  const results = [];
  const code = installClaudeCode(run, dryRun);
  if (code) results.push(code);
  for (const t of targets({ home, platform, env })) {
    if (!existsSync(t.dir)) continue;  // the app is not installed here
    results.push(t.toml ? installToml(t, command, dryRun) : installJson(t, command, dryRun));
  }
  return results;
}

export function report(results, dryRun = false) {
  if (!results.length) {
    return "No AI app found (Claude Code, Codex, Cursor, Windsurf, VS Code, Claude Desktop).\nSetup by hand: https://github.com/guardfix/guardfix#in-codex-cursor-vs-code-and-other-assistants-mcp";
  }
  const word = { added: dryRun ? "would add" : "added", already: "already there", skipped: "skipped" };
  const lines = results.map((r) => `  ${r.app.padEnd(15)} ${word[r.status]}${r.note ? `: ${r.note}` : ""}`);
  const out = ["GuardFix MCP server", ...lines];
  if (results.some((r) => r.status === "added") && !dryRun) {
    out.push("", "Restart those apps. Then ask your assistant: \"scan this project with guardfix\" or \"is axios 1.6.0 safe?\"",
      "Each changed file was backed up next to it as *.guardfix-backup.");
  }
  return out.join("\n");
}
