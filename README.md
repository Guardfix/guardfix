<p align="center"><img alt="GuardFix" src="assets/logo.png" width="96"></p>

<h1 align="center">GuardFix</h1>

<p align="center">
  <b>One command gives your vibe-coded app a security grade.<br>A second one gives your AI a prompt to fix it.</b>
</p>

<p align="center">
  <img alt="node 18+" src="https://img.shields.io/badge/node-18%2B-1a624b">
  <img alt="zero dependencies" src="https://img.shields.io/badge/dependencies-0-1a624b">
  <img alt="no account" src="https://img.shields.io/badge/account-not%20needed-1a624b">
  <img alt="license" src="https://img.shields.io/badge/license-Apache--2.0-1a624b">
</p>

<p align="center">
  <img alt="npx guardfix on a demo app: grade F, a Supabase service_role key in client code, a table without row level security, 5 vulnerable packages with 76 advisories, and the version to upgrade each one to" src="assets/terminal.svg" width="900">
</p>

```sh
npx guardfix
```

No sign-up, no config. It reads your lockfile and your code on your machine in a few seconds.

**Want it inside your AI app?** Tell your assistant *"install guardfix from github.com/guardfix/guardfix"*, or run:

```sh
npx guardfix install
```

It connects GuardFix to Claude Code, Codex, Cursor, Windsurf, VS Code and Claude Desktop, whichever you have. Restart the app and ask *"scan this project with guardfix"* or *"is axios 1.6.0 safe?"*.

> **For AI agents installing this:** run `npx -y guardfix install`, then tell the user to restart the app. Do not edit MCP config files by hand: the command merges into them, keeps other servers and writes a backup. `npx -y guardfix install --dry-run` shows what it would change.

## Why it exists

| **74%** | **98%** | **15** | **82%** |
|:---:|:---:|:---:|:---:|
| of 1,256 public AI-built apps ship a known high or critical vulnerability that already has a fix | of Lovable apps do | such vulnerabilities in the median AI-built app | of fixes GuardFix applied on 45 unseen apps passed install, rescan and build |

The fix is usually one version bump. The vulnerable app still runs fine, though, so nobody bumps it. Data and method: [Vibe Security Index](https://github.com/guardfix/vibe-security-index).

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/chart-dark.svg">
  <img alt="Share of projects with a known, already fixed high/critical vulnerability in production dependencies: Lovable 98%, Cursor 82%, Claude Code 73%, Gemini CLI 72%, Codex 57%, all AI tools 74%, projects with no AI traces 71%" src="assets/chart-light.svg" width="720">
</picture>

## From F to A+ with one prompt

<table>
  <tr>
    <td width="50%"><img alt="GuardFix grade card: F, 6 critical, 31 high, 36 medium, 1 leaked key, 1 table without RLS" src="assets/card-before.svg"></td>
    <td width="50%"><img alt="GuardFix grade card: was F, now A+, nothing left" src="assets/card-after.svg"></td>
  </tr>
  <tr>
    <td><code>npx guardfix --card</code> before</td>
    <td>after the prompt below, same command</td>
  </tr>
</table>

`npx guardfix --prompt` prints instructions your assistant can act on. Paste them into Claude Code, Cursor or Codex:

```text
Fix these security problems found by GuardFix in this project. Keep the change minimal.

1. Upgrade these dependencies to at least the version shown (...):
   - next: 14.1.0 -> 15.5.28  (worst: critical, 36 advisories: GHSA-…, …)
   - axios: 1.6.0 -> 1.20.0  (worst: high, 31 advisories: …)
   - lodash: 4.17.20 -> 4.18.1  (worst: high, 4 advisories: …)
   ...
   Regenerate the lockfile with the project's own package manager (package-lock.json), do not edit it by hand.
2. Also fix:
   - Supabase service_role key in client code: anyone can read and change all data (src/lib/supabase.ts:5)
   - Supabase table "profiles" has no row level security: ... (supabase/migrations/0001_init.sql)
   For a leaked key: move it to an environment variable on the server side, and tell me to rotate the key ...

Then: install from scratch, run the build and the tests, and run `npx guardfix` again.
```

Each version shown has been checked again in OSV. Advisories often get fixed one at a time: a plain "first fixed version" can still carry the next advisory. lodash 4.18.0 is one example. GuardFix keeps moving up until the version is clean.

Run `--card` again after fixing and the card shows **was F → now A+**. It also prints a README badge:

[![GuardFix grade](https://img.shields.io/badge/GuardFix-A%2B-brightgreen)](https://guardfix.io/vibe-security-index/?utm_source=badge)

## In Claude Code

```text
/plugin marketplace add guardfix/guardfix
/plugin install guardfix
/guardfix fix
```

On Claude Code 2.1.275 or later the install is one line: `/plugin install guardfix --marketplace guardfix/guardfix`. The plugin also brings the MCP tools below.

It checks the project and fixes what it can. It reinstalls, builds and checks again, then shows the grade before and after. It never prints key values. Before touching a database it shows you the RLS migration.

### It keeps watching while you code

The plugin also adds two hooks:

- **When a session starts**, it looks your locked versions up again and tells you what is new since last time: an advisory published for a package you use, or a vulnerable version an install brought in. *"GuardFix: new since 2026-11-18 — axios 1.7.4 (high) → 1.8.2. Run /guardfix fix"*. Nothing new, nothing said.
- **Before the AI writes a file**, it stops the edit if the edit adds a key to the code, a dependency pinned to a version with a known high or critical vulnerability, or a Supabase table without row level security. Claude gets the reason and what to do instead, and rewrites the edit: the key goes to an environment variable, the version goes up, the migration gets its policies. Only what the edit adds is checked, and a key in a git-ignored `.env` is fine.

Both send only package names and versions to OSV.dev, like the CLI. If OSV is unreachable they stay quiet and never block. `GUARDFIX_WATCH=0` turns off the session check, `GUARDFIX_GUARD=0` the guard. The watch state is kept in `~/.guardfix`, outside your project.

## In Codex, Cursor, VS Code and other assistants (MCP)

`npx guardfix install` does all of this for you. By hand: `npx guardfix mcp` runs the same checks as an [MCP](https://modelcontextprotocol.io) server. Your assistant gets three tools:

- `check_package`: is this version safe, and which version to use instead. The assistant calls it before it adds or pins a dependency.
- `scan`: the grade and every finding for the project.
- `fix_plan`: fix steps with exact versions and the RLS policies to add.

**Codex**
```bash
codex mcp add guardfix -- npx -y guardfix mcp
```
or in `~/.codex/config.toml`:
```toml
[mcp_servers.guardfix]
command = "npx"
args = ["-y", "guardfix", "mcp"]
```

**Claude Code without the plugin**
```bash
claude mcp add guardfix -- npx -y guardfix mcp
```

**Cursor** (`.cursor/mcp.json`), **Windsurf**, **Claude Desktop**
```json
{ "mcpServers": { "guardfix": { "command": "npx", "args": ["-y", "guardfix", "mcp"] } } }
```

**VS Code** (`.vscode/mcp.json`)
```json
{ "servers": { "guardfix": { "command": "npx", "args": ["-y", "guardfix", "mcp"] } } }
```

Like the CLI, it reads the project locally and sends only package names and versions to OSV.dev.

**Lovable, Bolt and other builders in the browser** cannot run local tools. Sync the project to GitHub, run `npx guardfix --prompt` on it and paste the result into the chat.

## What it checks

| | How | Why it matters for vibe-coded apps |
|---|---|---|
| **Vulnerable dependencies** | Reads the lockfile (npm, pnpm, yarn, bun, poetry, uv, requirements.txt) and looks up the exact versions in [OSV.dev](https://osv.dev) | 3 in 4 AI-built apps ship one |
| **Leaked keys** | OpenAI, Anthropic, Stripe live, AWS, GitHub and Google keys, private keys, and the **Supabase `service_role` key** in client code. A key in a local `.env` that git ignores is fine and is not counted | A key in the frontend bundle is public. A `service_role` key opens your whole database |
| **Supabase without RLS** | Tables of the `public` schema in `supabase/migrations` without `enable row level security`. Migrations are read in order, so RLS turned on later counts and removed tables are skipped. The owner column for the policy is named when it can be found | With RLS off, anyone holding your public anon key can read the table |

**Grade:** the worst problem decides it. Any critical issue gives F, and any high issue gives D. Medium and low issues give C, B or A. A clean project gets A+. Dev-only dependencies are listed separately and don't lower the grade. Without the dependency lookup (`--offline`, or OSV.dev unreachable) the grade is marked incomplete and no card or badge is made.

## Want it done for you, and proven?

[GuardFix](https://guardfix.io/cli/?utm_source=github) applies each fix in a sandbox before you see it: clean install, rescan with two scanners, build and tests. Then it opens a pull request. It also keeps watching the project and tells you when a new advisory hits a package you use.

| | `npx guardfix` (free) | [guardfix.io](https://guardfix.io/cli/?utm_source=github) |
|---|:---:|:---:|
| Grade, vulnerable deps, leaked keys, Supabase RLS | ✓ | ✓ |
| Prompt for your AI assistant | ✓ | ✓ |
| Fix applied and verified (install, rescan, build, tests) | | ✓ |
| Pull request with the verified fix | | ✓ |
| Alerts on new advisories | | ✓ |
| Live site check: headers, exposed files, trackers | | ✓ |

## Privacy

Only **package names and versions** leave your machine. They go to OSV.dev, which looks up the advisories. Your code and keys stay local. `--offline` skips the dependency lookup completely. Keys found in the code are always masked in the output.

## Options

| | |
|---|---|
| `npx guardfix [path]` | check a folder (default: current) |
| `--json` | machine-readable result |
| `--prompt` | fix instructions for your AI assistant |
| `--card` | write `guardfix-card.svg` and print a badge |
| `--offline` | no network: keys and Supabase only |

The exit code is 1 for grade D or F, which is handy in CI. It is 0 otherwise and 2 on errors. Requires Node 18+, no dependencies.

The pictures on this page come from a real run on a demo app with the old versions an assistant typically scaffolds: [`scripts/render-assets.js`](scripts/render-assets.js). The "after" card is the same app with the versions the check suggested, the key moved to an env variable and RLS on.

## Contact

Questions, false positives, a security report: [tech@guardfix.io](mailto:tech@guardfix.io) or an [issue](https://github.com/guardfix/guardfix/issues).

## License

Apache-2.0
