# AGENTS.md

Phishbowl is a self-hostable, vendor-neutral, **defensive-only** phishing triage tool: drop in a suspicious `.eml`/`.msg` and it parses the message, extracts and defangs IOCs, optionally enriches them via allowlisted OSINT APIs, computes a transparent risk score, and produces an analyst-ready report (self-contained HTML, rich CLI, and JSON). It is **offline-first** — the core pipeline (parse → extract → defang → score → report) always produces a complete verdict with zero API keys, and enrichment only augments. See `docs/PRD.md` for the full product spec and `docs/CHECKLIST.md` for the phased build order.

## Defensive invariants (non-negotiable — enforced in code and tested)

- **Never send.** No SMTP, no replies, no read receipts, no callback of any kind to the email's infrastructure.
- **Never detonate.** Attachments are hashed and inspected by metadata/magic bytes only — never executed, and archives are not auto-extracted.
- **Never fetch the analyzed email's URLs.** Phishbowl never opens the suspicious links. Indicators are only ever submitted to allowlisted third-party APIs the operator has configured.
- **Never auto-remediate.** Phishbowl produces a verdict and an optional playbook *draft*; it never quarantines, blocks, or acts.
- **The HTML report does zero network egress when opened** — no remote images, fonts, scripts, or trackers, and no beaconing. A report about a phishing email must never phone home to the attacker.
- **Only synthetic sample emails are ever committed.** Real phishing samples can carry live links, real PII, or actual malware — never commit one; synthesize fixtures instead.

## Working rules

- Start with the user's task and `git status --short --branch`; preserve unrelated work. This file is the operating contract; `CLAUDE.md` is a compatibility pointer.
- Run `make test` after a coherent batch of changes and before closeout. Reuse a passing result while its checked inputs remain unchanged; rerun after relevant edits. Report failures and checks that could not run accurately.
- Treat `docs/PRD.md` and `docs/CHECKLIST.md` as the source of truth; read the sections relevant to the task and reuse context already read unless it has changed.
- For phased implementation, build one phase at a time per `docs/CHECKLIST.md`; never jump ahead. A specific maintenance, review, or documentation request follows its own scope without advancing unrelated phases.
- Make routine, reversible choices within the task. Ask only when missing information materially changes the result or authorization and cannot be inferred; do not ask again for approval already given. Follow explicit user instructions for delivery, and create releases or tags only when requested.
- Keep CI minimal — never add GitHub Actions, coverage gates, or a type-checker. The routine gate is `make test` (a fast `pytest` run); bandit and pip-audit run once, only in the dedicated security step.
