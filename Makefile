# Phishbowl developer tasks. `make test` is the routine gate (CLAUDE.md):
# keep it cheap and fast. Heavier checks (bandit, pip-audit, release build)
# are run once, in their dedicated phases — never wired in here.

.PHONY: install format lint test screenshot demo

# Run tools via `$(PYTHON) -m` so they always come from the interpreter that
# has Phishbowl's dependencies installed — a bare `pytest`/`ruff` on PATH may
# live in an unrelated, isolated tool environment and fail to import them.
PYTHON ?= python3

install:
	$(PYTHON) -m pip install -e ".[dev]"

format:
	$(PYTHON) -m ruff format .

lint:
	$(PYTHON) -m ruff check .

test:
	$(PYTHON) -m pytest -q

# Regenerate the README's HTML-report screenshot from a synthetic fixture.
# Docs helper only — deliberately NOT part of `make test`. Renders to PNG via a
# headless Chromium (Playwright) if available, else writes the HTML and prints
# manual-capture instructions. See scripts/screenshot.sh.
screenshot:
	bash scripts/screenshot.sh

# Regenerate the README's terminal demo GIF from a synthetic fixture. Docs
# helper only — deliberately NOT part of `make test`. Drives scripts/demo.tape
# with VHS (needs vhs, ttyd, ffmpeg); prints install hints if VHS is absent.
# See scripts/demo.sh.
demo:
	bash scripts/demo.sh
