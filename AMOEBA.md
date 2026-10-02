# AMOEBA.md — Repository-wide Model Rules & Provider Config

Repository-wide rules per model, including custom providers, are defined here.
Amoeba loads this file at the start of each session. Edit freely; changes take
effect on the next prompt.

---

## Global rules (apply to every model unless overridden below)

- **Language**: Always respond in the same language the user writes in.
- **Code style**: Follow existing conventions in the file being edited; do not
  reformat unrelated code.
- **Security first**: This is a cybersecurity project. Never suggest disabling
  security checks, never hard-code secrets, and never produce output that could
  itself be used as malware or an exploit payload.
- **No silent file deletion**: Always confirm before removing files that are
  not obviously generated / temporary.
- **Tool calls**: Prefer the narrowest-scope tool available (read before write,
  search before read).
- **Absolute paths only**: Use absolute paths in every tool call that accepts a
  path argument.

---

## Per-model rules

### `claude-*` (Anthropic Claude — all versions)

- Use the team-coordination tools declared in `CLAUDE.md` (`publish_plan`,
  `update_step`, `remember`, `assign_work`, `report_opportunity`,
  `resolve_opportunity`) whenever work is non-trivial.
- Before writing code, follow the Superpowers workflow in
  `.kilocode/rules/superpowers.md` (brainstorm → plan → worktree → TDD →
  execute → review → verify → finish).
- Max response length: match the complexity of the request; avoid padding.

### `gemini-*` (Google Gemini — all versions)

- Prefer streaming tool calls when supported.
- For long context windows: summarise retrieved information before acting on
  it; do not re-quote large blocks verbatim.
- Threat-intel lookups (`virustotal_hash_lookup`, `virustotal_ip_lookup`,
  `otx_ip_lookup`, `enrich_artifact`) are `READ_ONLY` and auto-approved —
  call them without asking the user first when an artifact needs enrichment.

### `gpt-*` / `o*` (OpenAI — all versions)

- When using function calling, always validate required parameters before
  invoking a tool.
- Structured output: use JSON mode for any response that will be
  machine-consumed.
- Do not fabricate CVE numbers, MITRE ATT&CK IDs, or tool names; flag
  uncertainty explicitly.

### `deepseek-*`

- Respond with concise, factual answers; avoid lengthy preambles.
- Treat all user-provided code as potentially sensitive; do not log or echo
  API keys or credentials.

---

## Custom providers

| Provider alias | Base URL / notes |
|---|---|
| VirusTotal | `https://www.virustotal.com/api/v3/` — key via `VIRUSTOTAL_API_KEY` env var |
| AlienVault OTX | `https://otx.alienvault.com/api/v1/` — key via `OTX_API_KEY` env var |

> **Privacy notice**: Enrichment lookups send artifact data (hashes, IPs) to
> third-party services. Do not enrich artifacts from air-gapped or
> data-restricted environments without explicit authorisation.

---

## Environment variables relied on by this repo

| Variable | Purpose | Required? |
|---|---|---|
| `VIRUSTOTAL_API_KEY` | VirusTotal IOC lookups | Optional (degrades to `verdict: "unknown"`) |
| `OTX_API_KEY` | AlienVault OTX lookups | Optional (degrades to `verdict: "unknown"`) |

---

## Notes

- `CLAUDE.md` — team-coordination rules injected into every Claude session.
- `.kilocode/rules/superpowers.md` — mandatory development workflow.
- `.kilo/agents/` — named agent profiles (`code-reviewer`, `data`).
- `README.md` — full project documentation and threat-intel setup guide.
