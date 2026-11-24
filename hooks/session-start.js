#!/usr/bin/env node
// SessionStart hook: what is new in this project's dependencies. GUARDFIX_WATCH=0 turns it off.
import { watch } from "../src/watch.js";

async function stdin() {
  let data = "";
  for await (const chunk of process.stdin) data += chunk;
  try { return JSON.parse(data || "{}"); } catch { return {}; }
}

try {
  if (process.env.GUARDFIX_WATCH !== "0") {
    const event = await stdin();
    const result = await watch(event.cwd || process.cwd());
    if (result) {
      process.stdout.write(JSON.stringify({
        systemMessage: result.message,
        ...(result.context ? { hookSpecificOutput: { hookEventName: "SessionStart", additionalContext: result.context } } : {}),
      }));
    }
  }
} catch {
  // never in the way of a session
}
process.exit(0);
