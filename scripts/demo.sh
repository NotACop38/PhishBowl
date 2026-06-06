#!/usr/bin/env bash
# Record the README's terminal demo GIF from a bundled SYNTHETIC fixture.
#
# Docs/marketing helper, NOT part of the test gate (CLAUDE.md keeps `make test`
# cheap). Drives scripts/demo.tape with VHS to render docs/assets/demo.gif: the
# offline pipeline triaging a synthetic sample and printing a colorized verdict.
#
# Requires vhs, ttyd, and ffmpeg on PATH. If VHS is missing it prints install
# hints and exits without failing the build.
#
# Defensive: only ever runs PhishBowl on a synthetic fixture, never fetches the
# email's URLs, and the rendered report loads zero remote assets.
set -euo pipefail

cd "$(dirname "$0")/.."

FIXTURE="${FIXTURE:-tests/fixtures/crafted_malicious.eml}"
TAPE="scripts/demo.tape"

if ! command -v vhs >/dev/null 2>&1; then
  cat <<'EOF'
phishbowl/demo: vhs not found — cannot render docs/assets/demo.gif.

Install the recorder (all three are needed):
  go install github.com/charmbracelet/vhs@latest   # the recorder
  # plus ttyd and ffmpeg from your package manager, e.g.:
  #   apt-get install ttyd ffmpeg   /   brew install ttyd ffmpeg

Then re-run:  make demo
EOF
  exit 0
fi

# The tape types a clean `phishbowl analyze crafted_malicious.eml`, so stage the
# synthetic fixture under that bare name in the repo root for the recording and
# remove it (and the report the demo writes) afterwards.
STAGED="crafted_malicious.eml"
REPORT="report.html"
cleanup() { rm -f "$STAGED" "$REPORT"; }
trap cleanup EXIT

cp "$FIXTURE" "$STAGED"

echo "phishbowl/demo: recording $TAPE -> docs/assets/demo.gif"
vhs "$TAPE"
echo "phishbowl/demo: wrote docs/assets/demo.gif"
