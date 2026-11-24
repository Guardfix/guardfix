#!/usr/bin/env node
// PreToolUse hook on Write, Edit and MultiEdit: stops a key, a vulnerable pin or a table without RLS from being
// written. GUARDFIX_GUARD=0 turns it off; GUARDFIX_OFFLINE=1 skips the dependency lookup.
import { review, decision } from "../src/guard.js";

async function stdin() {
  let data = "";
  for await (const chunk of process.stdin) data += chunk;
  try { return JSON.parse(data || "{}"); } catch { return {}; }
}

try {
  if (process.env.GUARDFIX_GUARD !== "0") {
    const event = await stdin();
    const result = await review({ root: event.cwd || process.cwd(), tool: event.tool_name, input: event.tool_input,
      offline: process.env.GUARDFIX_OFFLINE === "1" });
    const answer = decision(result);
    if (answer) process.stdout.write(JSON.stringify(answer));
  }
} catch {
  // never in the way of an edit
}
process.exit(0);
