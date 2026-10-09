#!/usr/bin/env node
// scripts/test-frontend-changed.selftest.mjs
//
// Deterministic unit test for the pure mapping in test-frontend-changed.mjs.
// Runs no Jest and touches no git state — it only asserts that each kind of
// changed file selects the right SVS/Stai suite patterns. Exits non-zero on any
// mismatch so the routine can treat it as a fast regression check.
//
//   node scripts/test-frontend-changed.selftest.mjs

import {
  patternsForFile,
  selectPatterns,
  ALL_SVS_PATTERNS,
} from "./test-frontend-changed.mjs";

let failures = 0;

function eq(a, b) {
  if (a === b) return true;
  if (!Array.isArray(a) || !Array.isArray(b)) return false;
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

function check(label, actual, expected) {
  const ok = eq(actual, expected);
  if (!ok) {
    failures++;
    console.error(
      `FAIL: ${label}\n   expected: ${JSON.stringify(expected)}\n   actual:   ${JSON.stringify(actual)}`,
    );
  } else {
    console.log(`ok: ${label}`);
  }
}

// --- patternsForFile: precise tier ---------------------------------------
check(
  "StaiChatWorkspace component -> [StaiChatWorkspace]",
  patternsForFile("ui/hackerai/app/components/StaiChatWorkspace.tsx"),
  ["StaiChatWorkspace"],
);
check(
  "StaiChatWorkspace events test -> [StaiChatWorkspace]",
  patternsForFile(
    "ui/hackerai/app/components/__tests__/StaiChatWorkspace.events.test.ts",
  ),
  ["StaiChatWorkspace"],
);
check(
  "SvsCyberComposer component -> [SvsCyberComposer]",
  patternsForFile("ui/hackerai/app/components/SvsCyberComposer.tsx"),
  ["SvsCyberComposer"],
);
check(
  "SvsCyberModelSelector (no own test) -> composer consumer",
  patternsForFile("ui/hackerai/app/components/SvsCyberModelSelector.tsx"),
  ["SvsCyberComposer"],
);

// --- patternsForFile: shared tier ----------------------------------------
check(
  "stai-api module -> own suites + workspace consumer",
  patternsForFile("ui/hackerai/lib/stai-api.ts"),
  ["stai-api", "StaiChatWorkspace"],
);
check(
  "stai-api test file -> own suites + workspace consumer",
  patternsForFile("ui/hackerai/lib/__tests__/stai-api.approval.test.ts"),
  ["stai-api", "StaiChatWorkspace"],
);
check(
  "StaiGlobalState shared context -> workspace + composer",
  patternsForFile("ui/hackerai/app/contexts/StaiGlobalState.tsx"),
  ["StaiChatWorkspace", "SvsCyberComposer"],
);

// --- patternsForFile: widen tier (SVS/Stai files with no direct suite) ----
check(
  "svs/* subcomponent -> full SVS surface",
  patternsForFile("ui/hackerai/app/components/svs/SvsTranscript.tsx"),
  [...ALL_SVS_PATTERNS],
);
check(
  "SvsCyberReasoningPart -> full SVS surface",
  patternsForFile("ui/hackerai/app/components/SvsCyberReasoningPart.tsx"),
  [...ALL_SVS_PATTERNS],
);
check(
  "useSvsEventStream hook -> full SVS surface",
  patternsForFile("ui/hackerai/app/hooks/useSvsEventStream.ts"),
  [...ALL_SVS_PATTERNS],
);

// --- patternsForFile: not our surface -> null -----------------------------
check(
  "upstream HackerAI component -> null",
  patternsForFile("ui/hackerai/app/components/ChatInput/ChatInputToolbar.tsx"),
  null,
);
check(
  "upstream lib module -> null",
  patternsForFile("ui/hackerai/lib/api/agent-stream-runner.ts"),
  null,
);
check(
  "python source outside ui -> null",
  patternsForFile("cyber_tools.py"),
  null,
);

// --- normalization: Windows backslash paths -------------------------------
check(
  "backslash path is normalized",
  patternsForFile("ui\\hackerai\\lib\\stai-api.ts"),
  ["stai-api", "StaiChatWorkspace"],
);

// --- selectPatterns: dedup + stable order ---------------------------------
{
  const { patterns, matchedFiles } = selectPatterns([
    "ui/hackerai/app/components/StaiChatWorkspace.tsx",
    "ui/hackerai/app/components/SvsCyberComposer.tsx",
    "ui/hackerai/lib/stai-api.ts", // adds stai-api; StaiChatWorkspace already present
  ]);
  check("selectPatterns dedups + keeps order", patterns, [
    "StaiChatWorkspace",
    "SvsCyberComposer",
    "stai-api",
  ]);
  check("selectPatterns reports 3 matched files", matchedFiles.length, 3);
}
{
  const { patterns, matchedFiles } = selectPatterns([
    "cyber_tools.py",
    "README.md",
    "ui/hackerai/app/components/ChatInput/ChatInputToolbar.tsx",
  ]);
  check("selectPatterns ignores non-SVS files (patterns)", patterns, []);
  check("selectPatterns ignores non-SVS files (matched)", matchedFiles.length, 0);
}
{
  const { patterns } = selectPatterns([
    "ui/hackerai/app/components/svs/SvsWorkspaceHeader.tsx",
  ]);
  check("selectPatterns widens for untested svs/* file", patterns, [
    ...ALL_SVS_PATTERNS,
  ]);
}

if (failures > 0) {
  console.error(`\n${failures} assertion(s) failed.`);
  process.exit(1);
}
console.log("\nAll mapping assertions passed.");
