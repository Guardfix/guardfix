import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { install, report } from "../src/install.js";

const noClaude = () => ({ error: { code: "ENOENT" } });
function home() {
  const h = mkdtempSync(join(tmpdir(), "gf-home-"));
  mkdirSync(join(h, ".cursor"));
  mkdirSync(join(h, ".codex"));
  mkdirSync(join(h, "Library", "Application Support", "Code", "User"), { recursive: true });
  return h;
}
const opts = (h, extra = {}) => ({ home: h, platform: "darwin", env: {}, run: noClaude, command: "/usr/local/bin/npx", ...extra });

test("adds guardfix to every installed app and keeps other servers", () => {
  const h = home();
  writeFileSync(join(h, ".cursor", "mcp.json"), JSON.stringify({ mcpServers: { other: { command: "x" } } }));
  writeFileSync(join(h, ".codex", "config.toml"), 'model = "gpt"\n');
  const r = install(opts(h));
  assert.deepEqual(r.map((x) => `${x.app}:${x.status}`), ["Cursor:added", "VS Code:added", "Codex:added"]);
  const cursor = JSON.parse(readFileSync(join(h, ".cursor", "mcp.json"), "utf8"));
  assert.deepEqual(Object.keys(cursor.mcpServers), ["other", "guardfix"]);
  assert.deepEqual(cursor.mcpServers.guardfix, { command: "/usr/local/bin/npx", args: ["-y", "guardfix", "mcp"] });
  assert.ok(existsSync(join(h, ".cursor", "mcp.json.guardfix-backup")));
  const vscode = JSON.parse(readFileSync(join(h, "Library", "Application Support", "Code", "User", "mcp.json"), "utf8"));
  assert.equal(vscode.servers.guardfix.type, "stdio");
  const toml = readFileSync(join(h, ".codex", "config.toml"), "utf8");
  assert.match(toml, /^model = "gpt"\n\n\[mcp_servers\.guardfix\]\ncommand = "\/usr\/local\/bin\/npx"\nargs = \["-y", "guardfix", "mcp"\]\n$/);
  assert.match(report(r), /Restart those apps/);
});

test("a second run changes nothing, apps that are not installed are skipped", () => {
  const h = home();
  install(opts(h));
  const toml = readFileSync(join(h, ".codex", "config.toml"), "utf8");
  const r = install(opts(h));
  assert.ok(r.every((x) => x.status === "already"));
  assert.equal(readFileSync(join(h, ".codex", "config.toml"), "utf8"), toml);
  assert.ok(!r.some((x) => x.app === "Windsurf" || x.app === "Claude Desktop"));
});

test("broken JSON is left alone, dry run writes nothing", () => {
  const h = home();
  writeFileSync(join(h, ".cursor", "mcp.json"), "{ not json");
  const r = install(opts(h, { dryRun: true }));
  assert.equal(r.find((x) => x.app === "Cursor").status, "skipped");
  assert.equal(readFileSync(join(h, ".cursor", "mcp.json"), "utf8"), "{ not json");
  assert.ok(!existsSync(join(h, ".codex", "config.toml")));
  assert.match(report(r, true), /would add/);
});

test("Claude Code goes through its own CLI", () => {
  const calls = [];
  const run = (cmd, args) => { calls.push(args.join(" ")); return { status: args[1] === "get" ? 1 : 0 }; };
  const r = install(opts(mkdtempSync(join(tmpdir(), "gf-empty-")), { run }));
  assert.deepEqual(r, [{ app: "Claude Code", status: "added" }]);
  assert.equal(calls[1], "mcp add --scope user guardfix -- npx -y guardfix mcp");
});

test("nothing installed: says how to set up by hand", () => {
  assert.match(report(install(opts(mkdtempSync(join(tmpdir(), "gf-none-"))))), /No AI app found/);
});
