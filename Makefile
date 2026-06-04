# Phishbowl developer tasks. `make test` is the routine gate (CLAUDE.md):
# keep it cheap and fast. Heavier checks (bandit, pip-audit, release build)
# are run once, in their dedicated phases — never wired in here.

.PHONY: format lint test

format:
	ruff format .

lint:
	ruff check .

test:
	pytest -q
