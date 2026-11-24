// Builds a demo app in a temp folder, runs the real check on it (real OSV.dev lookup), and writes
// the README pictures from that run: assets/terminal.svg, assets/card-before.svg, assets/card-after.svg.
// Nothing here is drawn by hand: rerun `node scripts/render-assets.js` and the pictures follow the code.
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

Object.defineProperty(process.stdout, "isTTY", { value: true });  // keep the colours in text()
delete process.env.NO_COLOR;
const { check, text, card, byPackage } = await import("../src/cli.js");

const ASSETS = join(dirname(fileURLToPath(import.meta.url)), "..", "assets");
mkdirSync(ASSETS, { recursive: true });

// A typical vibe-coded app: versions as an AI assistant scaffolded them about a year ago.
const BEFORE = {
  next: "14.1.0", react: "18.2.0", "react-dom": "18.2.0", axios: "1.6.0", "@supabase/supabase-js": "2.39.0",
  lodash: "4.17.20", jsonwebtoken: "8.5.1", "path-to-regexp": "0.1.7",
};
const DEV = { vite: "5.0.0", postcss: "8.4.20" };
// Fake key that only looks like a Supabase service_role key, built at runtime so no key-like string is in git.
const fakeJwt = (role) => ["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
  Buffer.from(JSON.stringify({ iss: "supabase", ref: "demo", role })).toString("base64url"), "ZGVtby1zaWduYXR1cmUtbm90LXJlYWw"].join(".");

function app(deps, { key, rls }) {
  const root = join(mkdtempSync(join(tmpdir(), "gf-demo-")), "my-vibe-app");
  mkdirSync(join(root, "src", "lib"), { recursive: true });
  mkdirSync(join(root, "supabase", "migrations"), { recursive: true });
  const packages = { "": { name: "my-vibe-app" } };
  for (const [n, v] of Object.entries(deps)) packages[`node_modules/${n}`] = { version: v };
  for (const [n, v] of Object.entries(DEV)) packages[`node_modules/${n}`] = { version: v, dev: true };
  writeFileSync(join(root, "package-lock.json"), JSON.stringify({ name: "my-vibe-app", lockfileVersion: 3, packages }, null, 2));
  writeFileSync(join(root, "src", "lib", "supabase.ts"), key
    ? `import { createClient } from "@supabase/supabase-js";\n\nexport const supabase = createClient(\n  "https://demo.supabase.co",\n  "${fakeJwt("service_role")}"\n);\n`
    : `import { createClient } from "@supabase/supabase-js";\n\nexport const supabase = createClient(import.meta.env.VITE_SUPABASE_URL, import.meta.env.VITE_SUPABASE_ANON_KEY);\n`);
  writeFileSync(join(root, "supabase", "migrations", "0001_init.sql"),
    "create table public.profiles (id uuid primary key, email text);\ncreate table public.orders (id bigint primary key, user_id uuid, total numeric);\n" +
    (rls ? "alter table public.profiles enable row level security;\nalter table public.orders enable row level security;\n" : "alter table public.orders enable row level security;\n"));
  return root;
}

// --- ANSI text -> terminal SVG ------------------------------------------------------------------
const PALETTE = { 31: "#ff7a6b", 32: "#62d69e", 33: "#f2c14e" };
const FG = "#e4ede7", DIM = "#8aa397";
const esc = (s) => s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c]);

function spans(line) {  // -> [{text, color, bold, dim}]
  const out = [];
  let st = { color: null, bold: false, dim: false };
  for (const part of line.split(/(\x1b\[\d+m)/)) {
    const m = part.match(/^\x1b\[(\d+)m$/);
    if (!m) { if (part) out.push({ text: part, ...st }); continue; }
    const c = Number(m[1]);
    if (c === 0) st = { color: null, bold: false, dim: false };
    else if (c === 1) st = { ...st, bold: true };
    else if (c === 2) st = { ...st, dim: true };
    else st = { ...st, color: PALETTE[c] || null };
  }
  return out;
}

function wrap(line, width) {  // -> rows of spans; wraps on spaces and keeps the indent
  const plain = line.replace(/\x1b\[\d+m/g, "");
  if (plain.length <= width) return [spans(line)];
  const indent = plain.match(/^ */)[0].length + 2;
  const rows = [];
  let row = [], len = 0;
  for (const s of spans(line)) {
    for (const word of s.text.split(/(?<= )/)) {
      if (len + word.trimEnd().length > width && len > indent) {
        rows.push(row); row = [{ ...s, text: " ".repeat(indent) }]; len = indent;
      }
      row.push({ ...s, text: word }); len += word.length;
    }
  }
  rows.push(row);
  return rows;
}

function terminal(lines, title) {
  const W = 96, LH = 20, PAD = 22, TOP = 46;
  const rows = lines.flatMap((l) => wrap(l, W));
  const width = 900, height = TOP + PAD + rows.length * LH - 6;
  const body = rows.map((r, i) => {
    const t = r.map((s) => {
      const fill = s.color || (s.dim ? DIM : FG);
      return `<tspan fill="${fill}"${s.bold ? ' font-weight="700"' : ""}>${esc(s.text)}</tspan>`;
    }).join("");
    return `<text x="${PAD}" y="${TOP + PAD + i * LH}" xml:space="preserve" class="l" style="animation-delay:${(0.35 + i * 0.06).toFixed(2)}s">${t}</text>`;
  }).join("\n");
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace" font-size="13.5">
<style>.l{animation:in .25s ease-out backwards}@keyframes in{from{opacity:0}}@media (prefers-reduced-motion:reduce){.l{animation:none}}</style>
<rect width="${width}" height="${height}" rx="14" fill="#10211b"/>
<path d="M0 14a14 14 0 0 1 14-14h${width - 28}a14 14 0 0 1 14 14v20H0z" fill="#173b31"/>
<circle cx="22" cy="17" r="6" fill="#ff7a6b"/><circle cx="42" cy="17" r="6" fill="#f2c14e"/><circle cx="62" cy="17" r="6" fill="#62d69e"/>
<text x="${width / 2}" y="22" text-anchor="middle" fill="${DIM}" font-size="12.5">${esc(title)}</text>
${body}
</svg>
`;
}

// --- run ----------------------------------------------------------------------------------------
const before = app(BEFORE, { key: true, rls: false });
const t0 = performance.now();
const r1 = await check(before);
const seconds = ((performance.now() - t0) / 1000).toFixed(1);
if (r1.osvError) throw new Error(`OSV lookup failed: ${r1.osvError}`);
const out = text(r1).split("\n");
while (out.length && !out[0].trim()) out.shift();
while (out.length && !out.at(-1).trim()) out.pop();
writeFileSync(join(ASSETS, "terminal.svg"), terminal([`\x1b[32m❯\x1b[0m npx guardfix`, "", ...out], "~/my-vibe-app — npx guardfix"));
writeFileSync(join(ASSETS, "card-before.svg"), card(r1));

// After: every vulnerable package at the version the check asked for, key moved to env, RLS on.
const fixed = { ...BEFORE };
for (const g of byPackage(r1.findings)) if (g.fixed && g.package in fixed) fixed[g.package] = g.fixed;
const after = app(fixed, { key: false, rls: true });
const r2 = await check(after);
writeFileSync(join(ASSETS, "card-after.svg"), card(r2, r1.grade));

const n = (r, k) => r.findings.filter((f) => f.severity === k).length;
console.log(JSON.stringify({
  seconds, fixed,
  before: { grade: r1.grade, critical: n(r1, "critical"), high: n(r1, "high"), medium: n(r1, "medium"), packages: byPackage(r1.findings).length, yours: r1.index.yours },
  after: { grade: r2.grade, left: r2.findings.map((f) => `${f.package || f.id}@${f.version || ""} ${f.severity}`) },
}, null, 2));
for (const p of [before, after]) rmSync(dirname(p), { recursive: true, force: true });
