# Phishbowl

> Self-hostable, vendor-neutral, **defensive-only** phishing triage.

Drop in a suspicious `.eml`/`.msg` → parse it → extract and defang IOCs →
risk-score it → get an analyst-ready report. **Offline-first:** the core
pipeline produces a complete verdict with **zero API keys**. Optional OSINT
enrichment only augments.

> [!WARNING]
> **Early scaffold.** This repo is being built phase by phase per
> [`docs/CHECKLIST.md`](docs/CHECKLIST.md); most functionality isn't
> implemented yet. This README is a stub and will be polished as features land.

## Pipeline (target)

```
ingest → parse → extract → defang → score(offline) → [optional: enrich → re-score] → report
```

Outputs: a self-contained **HTML** report (the primary deliverable), a colorized
**CLI** summary, and complete **JSON** for piping to other tools.

## Safety (defensive-only)

Phishbowl analyzes emails you *received*, for triage. It **never** sends, never
detonates attachments, never fetches the email's URLs, and never
auto-remediates — and its HTML report performs **zero network egress** when
opened. See [`docs/PRD.md` §4](docs/PRD.md) and [`CLAUDE.md`](CLAUDE.md).

## Install (dev)

```bash
pip install -e ".[dev]"
```

Requires Python 3.11+.

## Develop

```bash
make test     # the routine gate — a fast pytest run
make lint     # ruff check
make format   # ruff format
```

## Docs

- [`docs/PRD.md`](docs/PRD.md) — product requirements (source of truth)
- [`docs/CHECKLIST.md`](docs/CHECKLIST.md) — phased engineering checklist
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — how to contribute (incl. the **no real samples** rule)

## License

MIT — see [`LICENSE`](LICENSE).
