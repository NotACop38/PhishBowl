"""Smoke test for the scaffold.

Trivial by design. ``make test`` is the routine gate (see CLAUDE.md /
docs/CHECKLIST.md), so it stays cheap and fast; meaningful coverage arrives
with each phase. This only confirms the package imports and the harness runs.
"""

import phishbowl


def test_package_exposes_version() -> None:
    assert isinstance(phishbowl.__version__, str)
    assert phishbowl.__version__
