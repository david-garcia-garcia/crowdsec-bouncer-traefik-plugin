# Test coverage

1. [hard] Critical path untested — `pkg/bouncer/bouncer_serve_lapi.go:72` — the live lookup passes the rule match to `appliedLAPIRemediation`; no test fails when that call ignores the match, so a softened ban could pass in live mode unseen
   Fix: Assert on a live-mode router that a captcha decision continues and a ban softened by the remap stays a ban on a bypassCaptcha request
   Status: done
   Argument: `TestBypassCaptcha_liveLookup` added; it fails when the live call site passes an empty match.
