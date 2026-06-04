# Contributing to Phishbowl

Thanks for your interest! Phishbowl is an early, phase-by-phase build. Please
read [`docs/PRD.md`](docs/PRD.md) (the product spec) and
[`CLAUDE.md`](CLAUDE.md) (the invariants and working rules) first — together
with [`docs/CHECKLIST.md`](docs/CHECKLIST.md) they are the source of truth.

## 🚫 Never commit real phishing samples

This is the single most important rule in the project.

**All fixtures and sample emails MUST be synthetic** — authored by us, using
`example.com`-class indicators and obviously-fake malicious markers.

**Never commit a real phishing email.** Real samples can carry:

- **live links** to attacker infrastructure (opening or leaking them can tip off the attacker or harm victims),
- **real PII** belonging to the people who were targeted,
- **actual malware** in their attachments.

Committing one is a security and privacy incident, not a shortcut. If you need
a sample to demonstrate a detection, **synthesize** one. Pull requests that add
real samples will be rejected.

## Defensive scope

Phishbowl is **defensive-only**. It never sends, never detonates attachments,
never fetches the analyzed email's URLs, and never auto-remediates — and the
HTML report does zero network egress when opened. Every contribution must
preserve these invariants (see [`CLAUDE.md`](CLAUDE.md)).

## Development

```bash
pip install -e ".[dev]"
make test     # routine gate — keep it green
make lint
make format
```

- Build one phase at a time per [`docs/CHECKLIST.md`](docs/CHECKLIST.md); don't jump ahead.
- Add tests alongside each feature.
- `make test` must be green before a change is considered done.
