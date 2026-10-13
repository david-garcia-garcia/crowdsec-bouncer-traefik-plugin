# Delivery

## Motivation

This ticket’s job is to close a proof gap against https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/397: the two edges that report named as failures in the other plugin were already this tree’s AppSec challenge protocol, and nothing here proved them.

#397 describes `action=challenge`, `http_status=200`, and empty or missing `user_body_content` coming back as HTTP 200 with an empty body, and a writer that already has `Content-Security-Policy` receiving a second CSP because `user_headers` were appended. The protocol is fail-closed to the configured ban response (status must not be committed before the empty-body check), same-name AppSec headers replace, and each `user_cookies` value stays its own `Set-Cookie`.

What was missing is proof of those two edges. The existing empty-challenge case used a nil ban template and only checked HTTP 403 plus the ban header, so it never showed the operator ban page and never sent an explicit empty-string `user_body_content`. The existing structured-challenge relay asserted one cookie via `Header().Get` and never pre-set CSP on the writer, so replace-versus-append and two separate `Set-Cookie` values were unobserved. The live challenge spec already named empty-challenge ban; it did not name CSP replace or separate cookies. Left alone, the two #397 edges stay an unproven claim.

Priority: P3 — a proof and spec gap with no current user or operator harm

## Implementation

The proof sits on the existing AppSec envelope test seam: the same `testBouncerWithAppsec` fixture and `handleNextServeHTTP` path as the other structured-challenge cases. One case table-drives omitted `user_body_content` (`{"action":"challenge","http_status":200}`) and explicit `user_body_content:""`, with a non-nil ban template, and asserts HTTP 403, `X-Remediation: ban`, and the rendered operator ban page for `192.0.2.10` — not HTTP 200 with an empty body. The other pre-sets `Content-Security-Policy: default-src 'self'` on the recorder, then AppSec returns `script-src 'none'` plus two `user_cookies`; it asserts `Header().Values` has exactly one CSP equal to the AppSec value and two separate `Set-Cookie` strings. Production was left unchanged. The live challenge spec gained the two header and cookie scenarios; empty-challenge ban was already named there.

## What this changes
**Operators.** None.
**Admin users.** None.
**Developers.** Keep the two #397 challenge invariants: empty or missing `user_body_content` is the operator ban page, same-name `user_headers` replace (one CSP), and each `user_cookies` value is its own `Set-Cookie`.
**End users.** None.
