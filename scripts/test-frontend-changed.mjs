#!/usr/bin/env node
// scripts/test-frontend-changed.mjs
//
// Change-aware Jest gate for the SVS/Stai frontend surface.
//
// WHY: the autonomous engineering routine verifies the Python suite every run,
// but the SVS/Stai additions to the vendored HackerAI UI (ui/hackerai) are only
// exercised when someone remembers to run Jest by hand. This script closes that
// gap: given the files that changed, it runs ONLY the SVS/Stai Jest suites those
// changes can affect, keeping the run scoped relative to the (very large)
// upstream HackerAI Jest suite while still catching our own regressions.
//
// It never modifies the vendored app: it lives at the repo root and shells into
// ui/hackerai to invoke `CI=true npx jest <patterns>`.
//
// USAGE:
//   node scripts/test-frontend-changed.mjs            # detect changes from git working tree, run
//   node scripts/test-frontend-changed.mjs --dry-run  # print the selection + command, run nothing
//   node scripts/test-frontend-changed.mjs --since <ref>   # also include files changed vs <ref>
//   node scripts/test-frontend-changed.mjs --files a,b,c    # use an explicit changed-file list
//   node scripts/test-frontend-changed.mjs --help
//
// EXIT CODES: 0 = suites passed (or nothing relevant changed); non-zero = Jest failed
// or a git/spawn error. The mapping itself is pure and unit-tested by
// scripts/test-frontend-changed.selftest.mjs.

import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const REPO_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
const UI_DIR = path.join(REPO_ROOT, "ui", "hackerai");
const UI_PREFIX = "ui/hackerai/";

// The Jest path-patterns that together cover every SVS/Stai test suite
// (patterns are matched as substrings against each test file's path by Jest):
//   StaiChatWorkspace -> StaiChatWorkspace.connection.test.tsx, StaiChatWorkspace.events.test.ts
//   SvsCyberComposer  -> SvsCyberComposer.commands.test.tsx
//   stai-api          -> stai-api.approval.test.ts, stai-api.commands.test.ts
//   SvsSensorStatus   -> SvsSensorStatus.test.tsx
// IMPORTANT: this set IS the widen-tier target, so EVERY SVS/Stai suite must be
// listed here. A suite missing from this list is silently skipped on a
// widen-tier change (regression fixed 2026-10-11: SvsSensorStatus.test.tsx had
// been added by the owner but no pattern matched it, so the gate never ran it).
export const ALL_SVS_PATTERNS = Object.freeze([
  "StaiChatWorkspace",
  "SvsCyberComposer",
  "stai-api",
  "SvsSensorStatus",
]);

function normalize(p) {
  return p.replace(/\\/g, "/");
}

// Pure mapping: a repo-relative changed path -> the Jest patterns to run for it.
// Returns `null` when the file is outside the SVS/Stai frontend surface (upstream
// HackerAI code, or any non-ui file), so callers can ignore it.
//
// Tiers (grounded in the import graph, verified 2026-10-05):
//   precise  -> a file backed by exactly the named suite(s)
//   shared   -> a module several tested components depend on
//   widen    -> an SVS/Stai file with no direct test (rendered/used across the
//               workspace); run the whole SVS/Stai surface to stay safe
export function patternsForFile(relPath) {
  const p = normalize(relPath);
  if (!p.startsWith(UI_PREFIX)) return null; // only the vendored UI matters
  const rest = p.slice(UI_PREFIX.length);
  if (!/stai|svs/i.test(rest)) return null; // not an SVS/Stai-owned file
  const base = rest.split("/").pop();

  // precise tier
  if (/StaiChatWorkspace/.test(base)) return ["StaiChatWorkspace"];
  if (/SvsCyberComposer/.test(base)) return ["SvsCyberComposer"];
  // SvsSensorStatus has its own dedicated suite (SvsSensorStatus.test.tsx).
  if (/SvsSensorStatus/.test(base)) return ["SvsSensorStatus"];
  // SvsCyberModelSelector has no own test; its only tested consumer is the composer.
  if (/SvsCyberModelSelector/.test(base)) return ["SvsCyberComposer"];
  // stai-api has its own suites AND is consumed by the workspace.
  if (/^stai-api\b/.test(base)) return ["stai-api", "StaiChatWorkspace"];
  // StaiGlobalState is the shared context; its tested consumers are workspace + composer.
  if (/StaiGlobalState/.test(base)) return ["StaiChatWorkspace", "SvsCyberComposer"];

  // widen tier: svs/* subcomponents, SvsCyberReasoningPart, useSvsEventStream,
  // and anything else SVS/Stai without a direct suite.
  return [...ALL_SVS_PATTERNS];
}

// Fold a list of changed files into the de-duplicated, order-stable set of
// patterns to run, plus the subset of files that matched (for logging).
export function selectPatterns(files) {
  const selected = [];
  const seen = new Set();
  const matchedFiles = [];
  for (const f of files) {
    const pats = patternsForFile(f);
    if (!pats) continue;
    matchedFiles.push(normalize(f));
    for (const pat of pats) {
      if (!seen.has(pat)) {
        seen.add(pat);
        selected.push(pat);
      }
    }
  }
  return { patterns: selected, matchedFiles };
}

function gitChangedFiles(opts) {
  const out = [];
  if (opts.since) {
    const diff = execFileSync(
      "git",
      ["diff", "--name-only", opts.since, "--", UI_PREFIX],
      { cwd: REPO_ROOT, encoding: "utf8" },
    );
    out.push(...diff.split(/\r?\n/).filter(Boolean));
  }
  // The routine operates on the uncommitted working tree, so always read it.
  // The `-- ui/hackerai` pathspec keeps the noisy .stai/ cache out of the scan.
  const status = execFileSync(
    "git",
    ["status", "--porcelain", "--", UI_PREFIX],
    { cwd: REPO_ROOT, encoding: "utf8" },
  );
  for (const line of status.split(/\r?\n/)) {
    if (!line.trim()) continue;
    let p = line.slice(3); // strip the "XY " status prefix
    if (p.includes(" -> ")) p = p.split(" -> ")[1]; // rename: take the new path
    p = p.replace(/^"|"$/g, ""); // unquote paths with special chars
    out.push(p);
  }
  return [...new Set(out)];
}

function parseArgs(argv) {
  const opts = { dryRun: false, since: null, files: null, help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--dry-run" || a === "--list") opts.dryRun = true;
    else if (a === "--help" || a === "-h") opts.help = true;
    else if (a === "--since") opts.since = argv[++i];
    else if (a.startsWith("--since=")) opts.since = a.slice("--since=".length);
    else if (a === "--files")
      opts.files = (argv[++i] || "").split(",").filter(Boolean);
    else if (a.startsWith("--files="))
      opts.files = a.slice("--files=".length).split(",").filter(Boolean);
    else {
      console.error(`[frontend-gate] unknown argument: ${a}`);
      process.exit(2);
    }
  }
  return opts;
}

const HELP = `Change-aware Jest gate for the SVS/Stai frontend surface.

Runs only the SVS/Stai Jest suites affected by the changed files.

  --dry-run, --list   Print the selected files, patterns, and command; run nothing.
  --since <ref>       Also include files changed vs a git ref (committed changes).
  --files a,b,c       Use an explicit comma-separated changed-file list (repo-relative).
  --help, -h          Show this help.

With no flags it reads the git working tree (staged + unstaged + untracked)
under ui/hackerai/. Exits non-zero when Jest fails.`;

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    console.log(HELP);
    return 0;
  }

  let changed;
  try {
    changed = opts.files ?? gitChangedFiles(opts);
  } catch (err) {
    console.error(
      `[frontend-gate] could not determine changed files: ${err.message}`,
    );
    return 2;
  }

  const { patterns, matchedFiles } = selectPatterns(changed);

  if (patterns.length === 0) {
    console.log(
      "[frontend-gate] No SVS/Stai frontend files changed — nothing to run.",
    );
    return 0;
  }

  console.log("[frontend-gate] Changed SVS/Stai files:");
  for (const f of matchedFiles) console.log(`  - ${f}`);
  console.log(`[frontend-gate] Jest patterns: ${patterns.join(" ")}`);
  console.log(
    `[frontend-gate] (cd ui/hackerai && CI=true npx jest ${patterns.join(" ")})`,
  );

  if (opts.dryRun) {
    console.log("[frontend-gate] --dry-run: not executing.");
    return 0;
  }

  const res = spawnSync("npx", ["jest", ...patterns], {
    cwd: UI_DIR,
    stdio: "inherit",
    env: { ...process.env, CI: "true" },
    shell: true, // npx resolves to npx.cmd on Windows; shell lets it be found
  });
  if (res.error) {
    console.error(`[frontend-gate] failed to launch jest: ${res.error.message}`);
    return 1;
  }
  return res.status == null ? 1 : res.status;
}

// Run the CLI only when executed directly; stay importable for the self-test.
if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main());
}
