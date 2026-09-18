# Explore
IssueKey: 2026-09-18-captcha-siteverify-ignores-http-status

Problem statement is `requirement.md` (not `ticket/`). `handoff.yaml` `qualify: qualified-with-gaps`. `comments: none` (no `comments.md`, no `[ ]` RETHINK). `openspec list --json`: no active change. Consumed `knowledge/devdocs/index.md`, `knowledge/research/index.md`, `index_core_plugin.md` (`core_plugin_middleware_captcha-gate`, `core_plugin_middleware_captcha-routing`), `index_std_go.md` (`std_go_test_zzz-prefix`). No `priority: always` packets. Research indexes have no hCaptcha / reCAPTCHA / Turnstile siteverify folders. No usage or Language write: gate and routing packets are enough to call those subsystems; "successful provider verify" is the ticket, not a new term. No research folder: official vendor pages define the verdict as JSON `success`, not HTTP status, so the 2xx gate is ours. Did not open `pkg/reclaim`. Identity is not reconstructed here (`Validate` does not choose `remoteIP`).

Reproduced on this worktree: throwaway `TestRepro_siteverifyHTTP500JSONSuccessMintsGate` (deleted after the run) POSTed a token to `ServeHTTP` with siteverify stub `WriteHeader(500)` + `Content-Type: application/json` + `{"success":true}`. Result: `status=302` and `Set-Cookie: crowdsec_captcha_gate=...`. Claim confirmed.

```
POST token
    │
    ▼
Validate
    ├─ PostForm err          → (false, err) → ServeHTTP 400     [PR #28 path; out of scope]
    ├─ Content-Type not JSON → (false, nil) → challenge 200
    ├─ decode err            → (false, err) → ServeHTTP 400
    └─ JSON success          → (success, nil)
         ▲
         └── StatusCode never read  ← DestBranch hole
    │
    ▼
valid true → mint crowdsec_captcha_gate + 302
```

## Concepts

**Siteverify**:
The provider HTTP POST `Validate` makes to `infoProvider.validate` (`secret` + `response`). Built-in URLs are hCaptcha / reCAPTCHA / Turnstile; custom uses `CaptchaCustomValidateURL`.

**Successful provider verify**:
What `ServeHTTP` treats as `valid == true` before minting `crowdsec_captcha_gate` and 302. DestBranch: JSON `Content-Type` prefix `application/json` plus decoded `success: true`. Desired: that, and only after a 2xx status.

**Failed verify**:
`valid == false` with no error. `ServeHTTP` re-renders the challenge at 200. Distinct from `Validate` returning an error (bare 400).

**Transport error**:
`PostForm` `err != nil`. DestBranch returns `(false, err)` → 400. PR #28 (open, not on dest) wanted that path to re-render 200. Out of scope here.

## Decisions

- Require 2xx on the received siteverify response before reading `success`. Check status before Content-Type and before decode.
- Non-2xx is a failed verify: `(false, nil)`. No gate cookie, no solved 302. Same return shape as the existing non-JSON Content-Type branch. Do not change `PostForm` `err` or JSON decode `err`.
- 2xx means status 200–299 inclusive (same band as LAPI `crowdsecQuery` first-digit `2`). Do not narrow to 200 only.
- Apply to every provider `Validate` already uses, including `custom`.
- Regression lives in this tree under `pkg/captcha/zzz_servehttp_test.go` (or a new `zzz_*_test.go` in that package). Assert no `crowdsec_captcha_gate` and not 302 on HTTP 500 + JSON `{"success":true}`. With `(false, nil)`, also assert challenge 200. Do not require the hunt name `TestHunt_siteverifyHTTPErrorDoesNotAcceptSuccessJSON`.
- Propose runs FindSpecHost. Intended host: new leaf `core_plugin_middleware_captcha-siteverify` (family already on dest). Do not fold the status rule into `core_plugin_middleware_captcha-gate` (that leaf owns the cookie after success). Do not revive #28's `core_plugin_captcha_handler` (not on dest).
- Leave Content-Type matching, `remoteip` on the siteverify POST, body drain, and PR #28 transport handling untouched.
- No `sync.Once` / package globals. No identity rewrite.

Official pages (fetched 2026-09-18) define the vendor verdict as JSON `success`, not HTTP status. Failed tokens are still a JSON body (hCaptcha / Google reCAPTCHA / Cloudflare Turnstile). Requiring 2xx before decode does not reject those documented failure bodies. They do not define non-2xx + `success: true` as a solve.

## Open questions

- Q: Non-2xx as `(false, nil)` (re-render challenge) vs `(false, err)` (HTTP 400)?
  Decision: assumed — `(false, nil)`. Ticket and hunt only forbid cookie + solved 302. Failed verify matches the Content-Type miss. Leave transport `(false, err)` on the #28 path.
  By: explore

- Q: What is 2xx?
  Decision: assumed — `status >= 200 && status < 300`. Same band as LAPI first-digit `2`. Requirement says 2xx, not 200-only.
  By: explore

- Q: Check status before or after Content-Type / decode?
  Decision: resolved — before both. Requirement: require 2xx before decoding `success`.
  By: explore

- Q: Where does the regression test live, and must it keep the hunt name?
  Decision: assumed — `pkg/captcha/` `zzz_*_test.go`; ServeHTTP asserts no gate cookie and not 302 (and 200 challenge if `(false, nil)`). Hunt name is not on dest; do not require it.
  By: explore

- Q: Which spec owns siteverify HTTP acceptance?
  Decision: resolved — new `core_plugin_middleware_captcha-siteverify` (FindSpecHost: new, high). Gate spec keeps cookie + first-solve 302 after success. Do not rename `captcha-gate`.
  By: propose

- Q: Does this work reconstruct client address, user, tenant, Host, or trust hop?
  Decision: resolved — none. `Validate` does not choose identity. `ServeHTTP` already receives `remoteIP` from `clientRequest`. Reuse that owner; do not add `remoteip` to siteverify in this change.
  By: explore

- Q: Drain the siteverify body on the new non-2xx return?
  Decision: assumed — no. Keep existing `defer` close, same as the Content-Type miss. Do not add a LAPI-style drain in this defect.
  By: explore

- Q: Log or metric on non-2xx?
  Decision: assumed — Debug with the status, sibling of `responseType:noJson`. No new metric.
  By: explore

- Q: Change Content-Type matching or PR #28 transport errors?
  Decision: resolved — no. Bound to this defect.
  By: explore
