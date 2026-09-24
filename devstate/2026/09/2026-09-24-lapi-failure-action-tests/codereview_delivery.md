# Delivery

## Motivation

`bouncerLapiFailureAction` already decides a request when LAPI cannot give a verdict. `passthrough` calls next. `ban` forbids. `captcha` serves the challenge. The stream client starts healthy and the first failed poll marks it unhealthy, so a cache miss then uses that knob.

The request tests never drove that poll. The stream case flipped the healthy flag by hand. `captcha` was asserted for an AppSec HTTP 500, not for a LAPI HTTP 500. A regression that banned on `passthrough` after a real stream 500, or that banned instead of challenging on a live LAPI 500, would stay green.

Priority: P3 — tests only, no current operator or end-user harm

## Implementation

Stream mode is constructed against an httptest LAPI that returns 500. The test waits until that constructor poll has fetched once and the client is unhealthy, then `ServeHTTP` checks `passthrough` and `ban`. Live mode is constructed against a LAPI that returns 500 with `captcha` and a challenge template, then `ServeHTTP` checks the remediation header and the page.

## What this changes
**Operators.** None.
**Admin users.** None.
**Developers.** None.
**End users.** None.
