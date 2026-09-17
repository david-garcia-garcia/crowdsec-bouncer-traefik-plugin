# Explore
IssueKey: 2026-09-06-upstream-357-appsec-captcha-action

## Concepts

```
AppSec listener 403 + JSON envelope
        │
        ▼
appsec.Client.Query  ── parse action / http_status / body / cookies / headers
        │
        ▼
applyAppsecServeHTTP
  allow / empty     → next
  ban               → operator banTemplate
  challenge + empty → ban
  any other action  → handleAppsecResponseServeHTTP (relay)
        │
        ▼
  action: captcha (this ticket) is that relay path,
  not pkg/captcha (LAPI / CrowdsecAppsecFailureAction)
```

**Structured AppSec response** (usage: `knowledge/devdocs/core_plugin_appsec.md`): JSON CrowdSec 1.8 returns (`action`, `http_status`, `user_body_content`, `user_cookies`, `user_headers`). Listener 403 is a verdict, not a transport failure. Owner: `pkg/appsec` parse, `pkg/bouncer` write.

**AppSec `action: captcha`**: a structured envelope action. On this fork it falls through the same relay as challenge HTML (`handleAppsecResponseServeHTTP`). It is not `pkg/captcha` and not `CrowdsecAppsecFailureAction=captcha`. Official protocol names captcha as a bouncer-rendered verdict; this product already chose envelope relay. Research: `knowledge/research/ext_crowdsec_appsec_protocol/`, `knowledge/research/ext_crowdsec_appsec_bot-detection/`.

**Challenge**: `action: challenge` with a non-empty body is relayed; empty body is a ban. Spec: `core_plugin_appsec_bot-detection`. Tests exist (`Test_appsecQuery_challengeJSON`, `TestHandleNextServeHTTPRelaysStructuredAppsecChallenge`). Captcha has the constant and the fall-through, no fixture.

Upstream #357's example body is `{"action":"captcha","http_status":403}` — no `user_body_content`. That envelope parses today and relays status 403 with an empty body. Challenge empty-body special-case does not apply.

## Decisions

- Bound action is **add-tests**. Do not change `applyAppsecServeHTTP` / `parseResponse` unless a test cannot be honest without a one-line correctness fix. No product captcha-provider wiring, no solved-captcha cache knob.
- Proof lives next to the existing challenge fixtures: `pkg/appsec/query_test.go` parse; `pkg/bouncer/bouncer_test.go` relay (status, body, headers, cookies, custom remediation header).
- Spec host is existing `core_plugin_appsec_bot-detection` (MODIFIED scenarios). The relay requirement already covers any non-allow/non-ban action; captcha is unproven, not a new capability. Do not add a new spec leaf.
- Empty-body captcha stays relay (status from `http_status`, no ban template, no `pkg/captcha`). Do not copy the challenge empty-body → ban special case. Upstream's own example has no body.
- Tests MUST NOT assert hCaptcha / reCAPTCHA / Turnstile / `pkg/captcha.ServeHTTP` for AppSec JSON captcha.
- No new research folder: protocol and bot-detection findings already name `action: captcha` on 403. No usage-packet produce: `core_plugin_appsec.md` already distinguishes AppSec captcha HTML from `pkg/captcha`.
- This work does not set or reconstruct client identity; AppSec already takes `clientRequest.remoteIP` from `pkg/ip.GetRemoteIP`. No reclaim / `New` lifetime change.

## Open questions

- Q: Should empty-body AppSec `action: captcha` ban like empty `challenge`, or relay status with no body?
  Decision: assumed — keep current relay (`handleAppsecResponseServeHTTP`); tests assert `http_status` (403 in the upstream example) and empty body, not the operator ban page.
  By: explore

- Q: Official docs treat captcha as a bouncer-rendered template; this fork relays the envelope like challenge. Which should tests lock?
  Decision: resolved — lock envelope parse + relay as implemented (`ActionCaptcha` + `handleAppsecResponseServeHTTP`). Switching to `pkg/captcha` is out of scope for add-tests.
  By: explore

- Q: Fold captcha scenarios onto `core_plugin_appsec_bot-detection` or create a new spec?
  Decision: assumed — MODIFIED on `core_plugin_appsec_bot-detection` (add parse + relay scenarios for `action: captcha`, including the no-body envelope). No new leaf.
  By: explore
