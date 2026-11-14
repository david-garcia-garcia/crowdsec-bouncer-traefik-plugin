# Explore
IssueKey: 2026-11-14-appsec-captcha-verdict

## Concepts

```
ServeHTTP
  action-rule ban ─────────────────────────────► ban page
  serveLAPI  (captcha decision → captcha gate; gate cleared → continue)
  serveAppSec
    captcha rule matched → applyCaptchaRuleServeHTTP → AppSec, then rule gate
    else applyAppsecServeHTTP
      allow / empty            → next
      ban                      → ban page (ban:appsec)
      challenge, empty body    → ban page (ban:appsec-challenge-empty)
      challenge + captcha rule → false (rule gate)
      captcha                  → handleAppsecResponseServeHTTP   ◄── today: blank 403
      any other action         → handleAppsecResponseServeHTTP   ◄── today: blank page when no body
  next

captcha gate (handleRemediationServeHTTP → handleCaptchaKindServeHTTP)
  unsubscribed / !Valid → ban (ban:captcha-downgrade)
  widget asset          → false
  Check(req) gate cookie valid → marker POST? 302 solved : false
  else captcha.ServeHTTP (Validate token → cookie + 302, or challenge page)
```

Units this change touches:

- `pkg/bouncer/bouncer.go` `applyAppsecServeHTTP` (verdict switch), `serveAppSec` (only caller of the non-rule AppSec path), `handleCaptchaKindServeHTTP` (captcha gate; also used by LAPI captcha, captcha rules, AppSec failure-action captcha).
- `pkg/bouncer/remediation_header.go` closed reason tokens and `formatAppsecRelayHeader`.
- `pkg/captcha` `Check`, `HasChallengeMarker`, `ServeHTTP` — reused, not changed.
- Specs `core_plugin_appsec_bot-detection` (relay + "AppSec captcha envelope" requirements), `core_plugin_middleware_bouncer` (header table `captcha:appsec`).
- Usage docs `core_plugin_appsec.md`, `core_plugin_middleware_captcha-routing.md` (term "Unsubscribed captcha" avoids AppSec captcha); README header table and AppSec section.

Call sites: `applyAppsecServeHTTP` has two callers (`serveAppSec`, `applyCaptchaRuleServeHTTP`); `handleCaptchaKindServeHTTP` one caller (`handleRemediationServeHTTP`); `handleAppsecResponseServeHTTP` one caller. Roots searched: `pkg/`, `plugin.go`, `zzz_*.go` at repo root.

Reproduce: `go test ./pkg/bouncer/ -run 'TestHandleNextServeHTTPEmptyCaptchaBodyRelaysStatus'` passes on `master` @ `3388bbca`: AppSec `{"action":"captcha","http_status":403}` → client gets 403 with an empty body and `X-Remediation: captcha:appsec`. That test locks the failure the review describes.

Outside facts: `knowledge/research/ext_crowdsec_appsec_protocol/` (updated this run: section "`captcha` is an official action and never carries a page", extracts `.sources/appsec-generate-response.md`, `.sources/lua-appsec-captcha.md`). Summary: `captcha` is one of CrowdSec's four official remediations; `GenerateResponse` never sends a body for `ban`, `captcha` or custom actions; the protocol makes the bouncer render `ban`/`captcha`; lua-cs-bouncer serves its captcha, validates the submission before AppSec, and bans unsupported actions; upstream #403 serves its captcha and validates the POST only when AppSec answers it with `captcha` again.

Upstream references: issues #357, #402 (point 3), #389, #354; PRs #343, #403 (commit 3), #428.

## Decisions

- AppSec `captcha` verdict → the existing captcha gate (`handleCaptchaKindServeHTTP`), metrics origin `appsec`, header `captcha:appsec`. Gate cleared → continue to `next`; no usable captcha client → downgrade ban (`ban:captcha-downgrade`). The envelope's `http_status` is not used (the captcha page has its own status), same as upstream.
- AppSec `captcha` while a captcha action rule matched → return false so the rule's gate runs, like a non-empty `challenge` today.
- AppSec action other than `allow`, `ban`, `captcha`, `challenge` with empty `user_body_content` → ban page with new closed reason `appsec-action-empty`. With a body → relay unchanged (no CrowdSec version sends one; keeps the existing contract).
- After AppSec lets a request through (allow, gate already cleared, or failure-action passthrough), a POST carrying challenge marker `crowdsec_captcha_challenge=v1` on a router with a usable captcha client goes to the captcha gate instead of `next`: first solve validates the token, a cleared gate gets the solved redirect. This is what makes an AppSec captcha solvable when the operator's rule does not match the form POST.
- Rejected: ban page for AppSec `captcha` (review's minimal proposal) — contradicts the protocol, which assigns `captcha` to the bouncer's own captcha, and the fork already has one per router.
- Rejected: relay `captcha` as today — CrowdSec never sends a captcha body, so the relay always writes an empty page.
- Rejected: validate the captcha submission before querying AppSec (lua) — the form POST would skip the WAF; validating after AppSec keeps AppSec bans on that POST.
- Rejected: a per-source solved state (lua) — the fork's gate is one HMAC cookie per router (`core_plugin_middleware_captcha-gate`), and the routing doc forbids reintroducing a server-side grace cache.
- Live contract: `openspec/specs/core_plugin_appsec_bot-detection/spec.md` (MODIFIED: relay requirement, captcha requirement replaced) and `openspec/specs/core_plugin_middleware_bouncer/spec.md` (MODIFIED: header table).

## Open questions

- Q: Should an AppSec `captcha` verdict serve the router's configured captcha, or only the ban page (the review's minimal step)?
  Rank: bounded asked — reverses requirement "AppSec captcha envelope is parsed and relayed" whose one caller (`applyAppsecServeHTTP`) and two locking tests were enumerated in `pkg/`; requirement.md Desired line 1 names remediating AppSec `captcha` as a captcha
  Decision: assumed — serve the configured captcha through `handleCaptchaKindServeHTTP`; no usable captcha client → `ban:captcha-downgrade`.
  By: explore

- Q: How is the captcha form POST validated when AppSec allows it (operator rule matches the GET but not the POST)?
  Rank: bounded incidental — changes `serveAppSec`, whose callers (ServeHTTP only) were enumerated, so a marker POST with no remaining remediation no longer reaches origin; no requirement line names it, it is a means to Desired line 1
  Decision: assumed — after AppSec lets the request through, a challenge-marker POST on a router with a usable captcha client goes to the captcha gate (validate, or solved redirect). Templates without the marker fall back to upstream's behavior (validated only when AppSec answers the POST with `captcha`).
  By: explore

- Q: Should a solved captcha clear only AppSec captchas (lua keeps per-source state) or every captcha on the router?
  Rank: additive incidental — reuses the existing gate cookie unchanged; no requirement line names it
  Decision: assumed — one gate cookie for every captcha source on the router, as LAPI, rule and failure-action captchas already share it, and as upstream does.
  By: explore

- Q: What should an AppSec action this bouncer cannot render (custom `SetRemediation("x")`) do?
  Rank: bounded asked — changes the relay branch of `applyAppsecServeHTTP` (one caller path enumerated); requirement.md Desired line 2
  Decision: assumed — empty `user_body_content` → ban page with `ban:appsec-action-empty`; non-empty body → relay unchanged.
  By: explore

- Q: Does this work set or reconstruct client identity?
  Rank: additive incidental — no identity field is produced; no requirement line names identity
  Decision: resolved — owner is `pkg/ip.GetRemoteIP` via `clientrequest.Request`; the captcha gate binds to `req.IPAddrString()` as it does for every other captcha source. Reuse it.
  By: explore

- Q: Is runtime behavior against a real CrowdSec 1.8 required before merge?
  Rank: additive incidental — proof only; requirement.md lists it under Unknowns
  Decision: assumed — envelope shape is settled from CrowdSec source (`GenerateResponse`); prove the plugin side with unit tests and a mock e2e scenario whose AppSec stand-in returns `{"action":"captcha","http_status":403}`. No real-stack hook scenario in this run.
  By: explore
