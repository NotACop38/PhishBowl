# Contributing to PhishBowl

Thanks for your interest. Before you start, read [`AGENTS.md`](AGENTS.md) (the
defensive invariants and working rules) and the parts of [`docs/PRD.md`](docs/PRD.md)
(the product specification) that touch your change.

## Never commit real phishing samples

This is the most important rule in the project.

**Every fixture and sample email must be synthetic**: written by you, using reserved
example indicators (`example.com`, `.example`, and the documentation IP ranges
`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and obviously fake malicious
markers.

**Never commit a real phishing email.** Real samples can carry:

- **live links** to attacker infrastructure (opening or leaking them can alert the
  attacker or harm victims);
- **real personal data** belonging to the people who were targeted;
- **actual malware** in their attachments.

Committing one is a security and privacy incident, not a shortcut. If you need a sample
to demonstrate a detection, synthesize one. Pull requests that add real samples will be
rejected. `tests/fixtures/build_synthetic_msg.py` shows how to build synthetic Outlook
`.msg` files.

## Defensive scope

PhishBowl is defensive-only. It never sends, never detonates attachments, never fetches
the analyzed email's URLs, and never auto-remediates, and the HTML report makes no
network requests when opened. Every contribution must preserve these invariants, which
the test suite enforces.

## Development

```bash
pip install -e ".[dev]"
make test         # the routine gate: keep it green
make lint         # ruff check
make format       # ruff format
make screenshot   # regenerate the README images (needs the Playwright CLI)
```

- Add or update tests with every change, including the unhappy paths: malformed input,
  hostile content, and failing services. Tests never reach the network; connectors are
  tested with mocked transports.
- Keep documentation in step with behavior: the README, the guides under `docs/`, and
  `CHANGELOG.md` (under *Unreleased*).
- CI stays minimal: no new GitHub Actions, coverage gates, or type checkers. Bandit and
  pip-audit run once, in the dedicated security step described in
  [`SECURITY.md`](SECURITY.md).
- To add an enrichment connector, follow [`docs/CONNECTORS.md`](docs/CONNECTORS.md).

## Reporting security issues

Report vulnerabilities privately, as described in [`SECURITY.md`](SECURITY.md), not in
a public issue.
