"""Red-team page for judges: visitors try to get a fake family's secrets out of the box.

Off by default. It only turns on for a dedicated demo home made with `familybox redteam init`, when the
box is started with `familybox redteam serve` (see docs/REDTEAM.md). The hooks live in
familybox/plugins/redteam.py; this package holds the logic:

  home.py      making and checking a dedicated demo home, and the on/off switch
  scoring.py   the independent leak checker, reused from eval/attacks.py
  ledger.py    spending guard, rate limits and the scoreboard (no IP addresses stored)
  guard.py     per-question tool limits that make the spending bound hold
  pages.py     the /redteam web page
"""
