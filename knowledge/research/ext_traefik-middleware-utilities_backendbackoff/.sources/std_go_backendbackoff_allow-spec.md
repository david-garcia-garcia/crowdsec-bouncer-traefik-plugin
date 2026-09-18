---
url: https://github.com/david-garcia-garcia/traefik-middleware-utilities/blob/950b08de86b6fd9ea68ac1d205e17a379ec60522/openspec/specs/std_go_backendbackoff_allow/spec.md
title: std_go_backendbackoff_allow
fetched: 2026-09-18
authority: official
ref: github.com/david-garcia-garcia/traefik-middleware-utilities@950b08de86b6fd9ea68ac1d205e17a379ec60522:openspec/specs/std_go_backendbackoff_allow/spec.md
---

Allow decides whether a real backend attempt may proceed. Report records that attempt’s boolean outcome. Caller owns identity; the library never reads HTTP.

Denied requests MUST NOT be treated as backend attempts. Denied Allows MUST NOT be Reported; if they are, the library ignores them the same as Report on OPEN with no outstanding probe.

New applies defaults for any zero field (Jitter 0 valid and disables jitter). Close drops keys; later Allow/Report error and MUST NOT admit.

Interpreted tests run Allow-then-Report trip with stdlib only and useunsafe false.
