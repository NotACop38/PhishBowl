#!/usr/bin/env bash
# Generate the README's HTML-report screenshot from a bundled SYNTHETIC fixture.
#
# This is a docs/marketing helper, NOT part of the test gate (CLAUDE.md keeps
# `make test` cheap). It does two things:
#   1. Always: run the offline pipeline on a synthetic fixture and write the
#      self-contained HTML report to docs/assets/sample-report.html.
#   2. If a headless Chromium is reachable via Playwright, render that HTML to
#      docs/assets/sample-report.png (full page) and a tighter hero crop. If not,
#      it prints clear manual-capture instructions instead of failing.
#
# Everything here is offline and defensive: it only ever renders a report built
# from a synthetic fixture — it never fetches the email's URLs (PhishBowl's job
# is done by the time the HTML exists) and the report itself loads zero remote
# assets.
set -euo pipefail

cd "$(dirname "$0")/.."

FIXTURE="${FIXTURE:-tests/fixtures/crafted_malicious.eml}"
OUT_DIR="docs/assets"
HTML="$OUT_DIR/sample-report.html"
PNG="$OUT_DIR/sample-report.png"
HERO="$OUT_DIR/sample-report-hero.png"
VIEWPORT="${VIEWPORT:-1200,900}"
HERO_VIEWPORT="${HERO_VIEWPORT:-1200,760}"
COLOR_SCHEME="${COLOR_SCHEME:-dark}"

mkdir -p "$OUT_DIR"

echo "phishbowl/screenshot: generating HTML report from $FIXTURE"
python -m phishbowl.cli analyze "$FIXTURE" --html "$HTML" >/dev/null
echo "phishbowl/screenshot: wrote $HTML"

render() {
  # render <viewport> <output> [--full-page]
  local viewport="$1" out="$2"; shift 2
  npx --yes playwright@latest screenshot \
    --browser chromium \
    --color-scheme "$COLOR_SCHEME" \
    --viewport-size "$viewport" \
    "$@" \
    "file://$(pwd)/$HTML" "$out"
}

if command -v npx >/dev/null 2>&1; then
  echo "phishbowl/screenshot: rendering PNGs with headless Chromium (Playwright)…"
  # On first run Playwright downloads a headless Chromium build automatically.
  if render "$VIEWPORT" "$PNG" --full-page && render "$HERO_VIEWPORT" "$HERO"; then
    echo "phishbowl/screenshot: wrote $PNG and $HERO"
    exit 0
  fi
  echo "phishbowl/screenshot: headless render failed — falling back to manual instructions." >&2
fi

cat <<EOF

phishbowl/screenshot: no headless renderer available.
The HTML report was still written to:

    $HTML

To capture the screenshots manually:
  1. Open $HTML in any browser (it loads zero remote assets — safe to open).
  2. Screenshot the full page  -> $PNG
     and the verdict banner    -> $HERO
  3. Re-run with Node available to automate it:  make screenshot

EOF
exit 0
