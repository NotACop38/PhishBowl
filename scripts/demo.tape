# VHS tape — records the README's terminal demo GIF.
#
# Renders docs/assets/demo.gif: the offline pipeline triaging a bundled
# SYNTHETIC fixture and printing a colorized verdict, with zero API keys and
# zero network egress. Regenerate with `make demo` (needs vhs, ttyd, ffmpeg).
#
# Defensive note: this only ever runs PhishBowl on a synthetic fixture. It
# never fetches the email's URLs and the rendered report loads zero remote
# assets — the same invariants the tool enforces everywhere else.

Output docs/assets/demo.gif

Set Shell "bash"
Set FontSize 13
Set Width 1100
Set Height 1340
Set Padding 22
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms
Set PlaybackSpeed 1.0

# Settle on a clean prompt.
Hide
Type "clear" Enter
Show
Sleep 600ms

# Triage a synthetic phishing sample, offline, and write a shareable report.
Type "phishbowl analyze crafted_malicious.eml --html report.html"
Sleep 700ms
Enter

# Let the verdict banner and per-rule breakdown render, then scroll through.
Sleep 5s
Sleep 3s
Sleep 2s
