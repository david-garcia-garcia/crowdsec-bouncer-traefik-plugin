# Nitpicks

1. [hard] Name for the scope — `pkg/bouncer/bouncer_serve_captcha.go:112` — `remediateWarnCaptchaRuleOnBan` now also returns without writing on a bypassed captcha; the name spells only the ban clause
   Fix: Rename to a name that covers both rule effects (`remediateUnderActionRules`) and say both in the comment
   Status: done
   Argument: renamed to `remediateUnderActionRules` with its three callers in `bouncer_serve_lapi.go`; comment lists both effects; usage doc, design and tasks follow.
