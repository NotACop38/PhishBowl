#!/usr/bin/env bash
# Regenerate the README's images from a bundled SYNTHETIC fixture.
#
# A docs helper, NOT part of the test gate (AGENTS.md keeps `make test` cheap).
# It always writes the self-contained HTML report (docs/assets/sample-report.html)
# and an HTML capture of the terminal summary. When the Playwright CLI and its
# Chromium are installed, it renders both to PNG:
#
#   docs/assets/sample-report.png       full report page
#   docs/assets/sample-report-hero.png  verdict banner and score breakdown
#   docs/assets/sample-cli.png          terminal summary
#
# Everything here is offline: the pipeline never fetches the email's URLs, and
# the rendered pages load no remote resources.
set -euo pipefail

cd "$(dirname "$0")/.."

PYTHON="${PYTHON:-python3}"
FIXTURE="${FIXTURE:-tests/fixtures/crafted_malicious.eml}"
OUT_DIR="docs/assets"
HTML="$OUT_DIR/sample-report.html"
PNG="$OUT_DIR/sample-report.png"
HERO="$OUT_DIR/sample-report-hero.png"
CLI_PNG="$OUT_DIR/sample-cli.png"
VIEWPORT="${VIEWPORT:-1200,900}"
HERO_VIEWPORT="${HERO_VIEWPORT:-1200,760}"
CLI_VIEWPORT="${CLI_VIEWPORT:-980,600}"
COLOR_SCHEME="${COLOR_SCHEME:-dark}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
CLI_HTML="$WORK/sample-cli.html"

mkdir -p "$OUT_DIR"

echo "phishbowl/screenshot: generating the HTML report from $FIXTURE"
# Exit status 1 (threshold) or 3 (incomplete) still means the report was written.
status=0
"$PYTHON" -m phishbowl.cli analyze "$FIXTURE" --quiet --html "$HTML" || status=$?
case "$status" in
  0 | 1 | 3) echo "phishbowl/screenshot: wrote $HTML" ;;
  *) echo "phishbowl/screenshot: analysis failed (exit $status)" >&2; exit "$status" ;;
esac

echo "phishbowl/screenshot: capturing the terminal summary"
"$PYTHON" - "$FIXTURE" "$CLI_HTML" <<'PY'
import io
import sys

from rich.console import Console
from rich.terminal_theme import MONOKAI

from phishbowl.parse import parse
from phishbowl.pipeline import triage
from phishbowl.report import render_cli

fixture, out = sys.argv[1], sys.argv[2]
view, _ = triage(parse(fixture))
console = Console(
    record=True, width=100, force_terminal=True, color_system="truecolor", file=io.StringIO()
)
console.print(f"$ phishbowl analyze {fixture.rsplit('/', 1)[-1]}", style="bold")
render_cli(view, console)
console.save_html(out, theme=MONOKAI)
PY

render() {
  # render <viewport> <absolute page path> <output> [--full-page]
  local viewport="$1" page="$2" out="$3"; shift 3
  playwright screenshot \
    --browser chromium \
    --color-scheme "$COLOR_SCHEME" \
    --viewport-size "$viewport" \
    "$@" \
    "file://$page" "$out" >/dev/null
}

if command -v playwright >/dev/null 2>&1; then
  echo "phishbowl/screenshot: rendering PNGs with headless Chromium (Playwright)"
  if render "$VIEWPORT" "$(pwd)/$HTML" "$PNG" --full-page \
    && render "$HERO_VIEWPORT" "$(pwd)/$HTML" "$HERO" \
    && render "$CLI_VIEWPORT" "$CLI_HTML" "$CLI_PNG" --full-page; then
    echo "phishbowl/screenshot: wrote $PNG, $HERO and $CLI_PNG"
    exit 0
  fi
  echo "phishbowl/screenshot: headless rendering failed." >&2
  exit 1
fi

cat <<MSG

phishbowl/screenshot: the Playwright CLI is not installed, so no PNGs were rendered.
The HTML report was written to $HTML (it loads no remote resources).

To render the images, install Playwright and its Chromium, then run:  make screenshot

MSG
