"""Connector discovery: in-repo registry + entry-points (PRD §9).

Two discovery paths, by design (PRD §9, "Discovery"):

* an **in-repo registry** — the :func:`register` decorator the bundled connectors
  use (and any connector shipped inside this repo); and
* the **``phishbowl.connectors`` entry-point group** — so a third party can
  ``pip install`` a connector package that auto-registers *without forking*.

:func:`discover` merges both into ``{name: class}``. Entry-point loading is fully
guarded: a broken or malicious third-party package can fail to import without
taking down discovery (or the run) — it is logged and skipped (PRD §11).
"""

from __future__ import annotations

import importlib
import logging
from importlib import metadata

from .base import Connector

log = logging.getLogger(__name__)

ENTRY_POINT_GROUP = "phishbowl.connectors"

# Module path of the bundled connectors; importing it runs their @register calls.
_BUILTIN_MODULE = "phishbowl.connectors.builtin"

_REGISTRY: dict[str, type[Connector]] = {}


def register(cls: type[Connector]) -> type[Connector]:
    """Class decorator: add a connector to the in-repo registry under its ``name``.

    The bundled connectors use this; so can any connector that lives in this repo.
    Third-party pip packages instead advertise a ``phishbowl.connectors``
    entry-point (no decorator, no import side effects required of the host).
    """
    if not cls.name:
        raise ValueError(f"connector {cls.__name__} must set a non-empty 'name'")
    _REGISTRY[cls.name] = cls
    return cls


def _load_builtins() -> None:
    """Import the bundled connectors so their :func:`register` decorators run."""
    importlib.import_module(_BUILTIN_MODULE)


def _iter_entry_points() -> list[metadata.EntryPoint]:
    try:
        return list(metadata.entry_points(group=ENTRY_POINT_GROUP))
    except Exception:  # pragma: no cover - importlib.metadata edge cases
        log.warning("could not enumerate %s entry points", ENTRY_POINT_GROUP)
        return []


def discover(*, include_entry_points: bool = True) -> dict[str, type[Connector]]:
    """Return all known connectors as ``{name: class}`` (registry + entry-points).

    In-repo registrations win over entry-points on a name clash, so a third party
    can't shadow a bundled connector. Any entry-point that fails to load is logged
    and skipped — never fatal.
    """
    _load_builtins()
    classes: dict[str, type[Connector]] = dict(_REGISTRY)
    if include_entry_points:
        for ep in _iter_entry_points():
            if ep.name in classes:
                continue
            try:
                loaded = ep.load()
            except Exception:  # a third-party packaging error must not crash discovery
                log.warning("failed to load connector entry point %r", ep.name)
                continue
            if isinstance(loaded, type) and issubclass(loaded, Connector) and loaded.name:
                classes.setdefault(loaded.name, loaded)
            else:
                log.warning("entry point %r is not a Connector subclass; skipping", ep.name)
    return classes
