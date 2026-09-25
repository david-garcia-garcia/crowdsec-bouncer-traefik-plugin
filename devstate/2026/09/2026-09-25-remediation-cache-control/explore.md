# Explore

Problem this run covers: a CDN in front of Traefik stored this plugin’s captcha HTML (HTTP 200 on the original URL, Content-Type only, no Set-Cookie). After the captcha decision was cleared, the CDN kept serving that stored page. Desired: set `Cache-Control: no-cache, no-store` on the captcha challenge writer and the ban-page writer, matching CrowdSec HAProxy SPOA and the AppSec challenge protocol example.

## Concepts

Units this change would touch:

- `captcha.Client.ServeHTTP` — `pkg/captcha/captcha.go` — challenge HTML path: `Content-Type` from the template, optional remediation header, `WriteHeader(200)`, execute template. No `Cache-Control`. Gate cookie only on `Pass` before the 302.
- `Bouncer.handleBanServeHTTP` — `pkg/bouncer/bouncer.go` — operator ban page: optional remediation header, `Content-Type` from `banTemplateContentType`, `WriteHeader(remediationStatusCode)`, template when present and method is not HEAD. No `Cache-Control`.
- Captcha ServeHTTP tests — `pkg/captcha/zzz_servehttp_test.go` — assert 200 + body and solve 302 + gate cookie; do not assert `Cache-Control`.
- Ban ServeHTTP tests — `pkg/bouncer/zzz_bouncer_test.go` (`TestHandleBanServeHTTP*` / `TestHandleBanServeHTTPContentType`) — assert status, remediation header, body, `Content-Type`; do not assert `Cache-Control`.
- AppSec envelope relay — `handleAppsecResponseServeHTTP` — copies `user_headers` (hop-by-hop and `Set-Cookie` skipped). Out of scope; already relays engine `Cache-Control` when present.

```
handleRemediationServeHTTP
        │
        ├── captcha kind, subscribed, usable client
        │         ├── custom-resource / Check-true form 302 / origin
        │         └── captcha.ServeHTTP
        │                   ├── Pass → gate cookie + 302   (out of scope)
        │                   └── else → 200 challenge HTML  ← set Cache-Control here
        └── ban kind (and captcha fallbacks)
                  └── handleBanServeHTTP               ← set Cache-Control here

handleAppsecResponseServeHTTP  → relay user_headers as-is   (out of scope)
```

Call sites that matter (roots searched: worktree `pkg/**/*.go` for `func (c *Client) ServeHTTP`, `captchaClient.ServeHTTP`, `handleBanServeHTTP(`):

- Challenge writer `Client.ServeHTTP`: **1** production caller (`handleRemediationServeHTTP`).
- Ban writer `handleBanServeHTTP`: **1** definition; **10** production call sites in `pkg/bouncer/bouncer.go` (all inherit one header Set); **3** direct test calls in `pkg/bouncer/zzz_bouncer_test.go`.

Reproduce:

1. Captcha challenge HTML omits `Cache-Control` — **pass** (header absent on dest). Throwaway `TestExploreChallengeHTMLOmitsCacheControl` (deleted after run): GET `ServeHTTP` → HTTP 200, `Cache-Control` empty, no `Set-Cookie`.
2. Ban HTML omits `Cache-Control` — **pass** (header absent on dest). Throwaway `TestExploreBanHTMLOmitsCacheControl` (deleted after run): `handleBanServeHTTP` GET → HTTP 403, `Cache-Control` empty.
3. CDN kept serving the stored captcha page after the decision was cleared — **not reproduced** (deployment not in this tree; Out of scope names CDN configuration).

Outside facts used: `knowledge/research/ext_crowdsec_bouncers_cache-control/` (HAProxy SPOA and AppSec challenge protocol both use exactly `no-cache, no-store`). In-tree `knowledge/research/ext_crowdsec_appsec_bot-detection/` names `Cache-Control` on `user_headers` but not the value. Usage: `knowledge/devdocs/core_plugin_middleware_captcha-widget.md`, `core_plugin_middleware_captcha-routing.md`, `core_plugin_appsec.md`. Test-file naming: `knowledge/devdocs/std_go_test_zzz-prefix.md`. No `priority: always` packets. `openspec list --json`: no active change.

This work does not reconstruct identity. Ban-page `ClientIP` stays `req.remoteIP` from `pkg/ip.GetRemoteIP`. Captcha `ServeHTTP` already receives that owner output as `remoteIP`.

## Decisions

- Chosen seam: `Header().Set("Cache-Control", "no-cache, no-store")` on the two existing writers, next to `Content-Type` and before `WriteHeader`.
- Chosen value: exactly `no-cache, no-store`. Vendor confirmation is the HAProxy SPOA returns, the SPOA Go writer default, the AppSec protocol example, and engine `setChallengeResponse`.
- Chosen tests: assert that header on the existing challenge 200 and ban header tests in the two Affected files (`pkg/captcha/zzz_servehttp_test.go`, `pkg/bouncer/zzz_bouncer_test.go`). Do not add a new neighbor test file.
- Rejected: setting `Cache-Control` on `Pass` 302 / `WriteSolvedRedirect` — Out of scope names the challenge HTML response.
- Rejected: adding `Set-Cookie` on the challenge page, changing HTTP 200 or the ban status, CDN configuration — Out of scope.
- Rejected: changing AppSec relay — it already copies `user_headers`; leave the mock `"Cache-Control":["no-store"]` fixtures as relay input.
- Rejected: extra directives (`private`, `max-age=0`, `must-revalidate`, `Pragma`) — no official owner uses them.
- Rejected: a shared helper package or Traefik Config field — two writers already own their response headers.
- Live contract: `openspec/specs/core_plugin_middleware_captcha-widget/spec.md` owns challenge `ServeHTTP` render (no Cache-Control SHALL today). `openspec/specs/core_plugin_middleware_bouncer/spec.md` names ban pages as bouncer request policy but has no header SHALL. `openspec/specs/core_plugin_appsec_bot-detection/spec.md` owns envelope relay (out of scope). Propose adds a SHALL on the captcha-widget challenge 200 and a ban-page header requirement on the bouncer spec.

## Open questions

- Q: Do live HAProxy SPOA and the AppSec protocol example use exactly `no-cache, no-store`, or extra directives?
  Rank: additive asked — new header on two writers this change owns; Desired names match CrowdSec `no-cache, no-store`
  Decision: resolved — exactly `no-cache, no-store`; HAProxy SPOA docs/config/Go writer and AppSec challenge protocol example plus engine `setChallengeResponse` agree; no extra directives
  By: explore

- Q: Must existing header tests gain Cache-Control assertions, or is a new neighbor test the right place?
  Rank: additive asked — Affected names pkg/captcha/zzz_servehttp_test.go and pkg/bouncer/zzz_bouncer_test.go
  Decision: assumed — extend those existing header tests (challenge 200 body case and TestHandleBanServeHTTPContentType / method table); do not add a new zzz_ file
  By: explore

- Q: What is the CDN cache-key / TTL behaviour in the reported deployment?
  Rank: additive incidental — Out of scope names CDN configuration; no existing plugin contract is reshaped
  Decision: assumed — unknown and not in this tree; do not model cache keys or TTLs; the plugin lever is Cache-Control on the two writers
  By: explore

- Q: Should the Pass 302 / WriteSolvedRedirect paths also set Cache-Control?
  Rank: additive incidental — Out of scope names the Pass 302 / WriteSolvedRedirect path; ticket names the 200 challenge HTML
  Decision: assumed — no; leave those redirects unchanged
  By: explore

- Q: Should AppSec challenge relay start emitting Cache-Control when the engine omits it?
  Rank: additive incidental — Out of scope names handleAppsecResponseServeHTTP; it already copies user_headers
  Decision: assumed — no; leave relay and its no-store mock fixtures unchanged
  By: explore

- Q: Should HEAD and nil-banTemplate responses get Cache-Control?
  Rank: additive asked — Desired names handleBanServeHTTP and Client.ServeHTTP, which already set Content-Type before WriteHeader on those branches
  Decision: assumed — yes; set the header on the writer before WriteHeader so HEAD and empty-body bans carry it the same as Content-Type
  By: explore

- Q: Should a shared helper or Config field own the header string?
  Rank: additive incidental — no criterion names a helper or config key; two existing writers already own response headers
  Decision: assumed — no new package and no Traefik Config field; unexported const or identical literal next to each Set is enough
  By: explore

- Q: Should live specs name Cache-Control on challenge HTML and the ban page?
  Rank: additive incidental — no In-scope line names a spec edit; adding SHALLs leaves existing callers working
  Decision: assumed — propose adds a challenge-200 Cache-Control scenario to core_plugin_middleware_captcha-widget and a ban-page header requirement to core_plugin_middleware_bouncer
  By: explore

- Q: Should e2e assert Cache-Control?
  Rank: additive incidental — Affected names the two unit test files, not e2e
  Decision: assumed — no; unit tests on the two writers are enough
  By: explore
