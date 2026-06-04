# Phishbowl developer tasks. `make test` is the routine gate (CLAUDE.md):
# keep it cheap and fast. Heavier checks (bandit, pip-audit, release build)
# are run once, in their dedicated phases — never wired in here.

.PHONY: format lint test screenshot

format:
	ruff format .

lint:
	ruff check .

test:
	pytest -q

# Regenerate the README's HTML-report screenshot from a synthetic fixture.
# Docs helper only — deliberately NOT part of `make test`. Renders to PNG via a
# headless Chromium (Playwright) if available, else writes the HTML and prints
# manual-capture instructions. See scripts/screenshot.sh.
screenshot:
	bash scripts/screenshot.sh
