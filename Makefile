# PhishBowl developer tasks. `make test` is the routine gate (AGENTS.md):
# keep it cheap and fast. Heavier checks (bandit, pip-audit, release build)
# are run once, in their dedicated phases — never wired in here.

.PHONY: install format lint test screenshot

# Run tools via `$(PYTHON) -m` so they always come from the interpreter that
# has PhishBowl's dependencies installed — a bare `pytest`/`ruff` on PATH may
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

# Regenerate the README's images (HTML report and terminal summary) from a
# synthetic fixture. Docs helper only — deliberately NOT part of `make test`.
# Renders PNGs with headless Chromium when the Playwright CLI is installed;
# otherwise writes the HTML report and says what is missing. See
# scripts/screenshot.sh.
screenshot:
	PYTHON="$(PYTHON)" bash scripts/screenshot.sh
