"""Tests for the stub ``analyze`` CLI command (Phase 0).

The pipeline isn't built yet; all we assert is that the command loads the
synthetic fixture into a ``ParsedEmail`` with a populated ``Source`` and
rejects bad input gracefully (no crash, no parsing).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from phishbowl.cli import app, load_stub
from phishbowl.models import EmailFormat, ParsedEmail

FIXTURE = Path(__file__).parent / "fixtures" / "benign_newsletter.eml"

runner = CliRunner()


def test_load_stub_returns_parsed_email_with_source() -> None:
    parsed = load_stub(FIXTURE)

    assert isinstance(parsed, ParsedEmail)
    assert parsed.source.filename == "benign_newsletter.eml"
    assert parsed.source.format is EmailFormat.EML
    assert parsed.source.parser_version
    # Stub only: nothing downstream of Source is populated yet.
    assert len(parsed.headers) == 0
    assert parsed.subject is None


def test_load_stub_rejects_unsupported_suffix(tmp_path: Path) -> None:
    bogus = tmp_path / "notes.txt"
    bogus.write_text("not an email")
    with pytest.raises(ValueError):
        load_stub(bogus)


def test_load_stub_missing_file() -> None:
    with pytest.raises(FileNotFoundError):
        load_stub("/does/not/exist.eml")


def test_analyze_command_runs_on_fixture() -> None:
    result = runner.invoke(app, ["analyze", str(FIXTURE)])

    assert result.exit_code == 0
    assert "benign_newsletter.eml" in result.stdout
    assert "format=eml" in result.stdout
