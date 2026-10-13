## Motivation
Captcha gate cookie `crowdsec_captcha_gate` and CrowdSec AppSec bot-detection cookie `__crowdsec_challenge` both need the client-facing scheme. Traefik may leave `X-Forwarded-Proto` when the entrypoint trusts forwarded headers; `Request.TLS` is the socket to Traefik and is often nil after TLS termination. GetRemoteIP already chose the client address. It does not own scheme.

The captcha gate set `Secure` when `Request.TLS` was non-nil **or** trimmed `X-Forwarded-Proto` EqualFold `https` (whole value). Captcha read proto and TLS itself. Explicit proto `http` with TLS set still got `Secure`. AppSec `X-Crowdsec-Appsec-Uri` was `httpReq.URL.String()`. A normal Traefik server request is origin-form: empty `URL.Scheme` and `URL.Host`, path and query only (`/foo?q=1`). CrowdSec 1.8 parses that header into `request.URL` and sets `__crowdsec_challenge` `Secure` iff `request.URL.Scheme == "https"`. Path-only URI yields an empty Scheme, so the challenge cookie is not `Secure` even when the browser is on HTTPS.

Left alone, HTTPS clients behind Traefik receive the challenge cookie without `Secure`. The two cookies can disagree: gate `Secure` from the OR, challenge never `Secure` on origin-form. Proto `http` plus TLS over-marks the gate cookie `Secure`. Nothing asserted `Secure` on both cookies together.

Priority: P2 — HTTPS clients get the AppSec challenge cookie without Secure, limited to bot-detection and that cookie

## Implementation
`pkg/clientrequest.New` fills one inbound `Request` after GetRemoteIP. The constructor owns the scheme token: trimmed `X-Forwarded-Proto` whole-value EqualFold `http` or `https` wins; otherwise TLS non-nil is `https`, else `http`. Values that are not an exact proto (`wss`, empty, `https,http`, `URL.Scheme`) fall through to TLS. Callers do not assign scheme. The live `*http.Request` is not written.

Captcha `ServeHTTP`, `Check`, `Validate`, and `setGateCookie` take that value. Gate cookie `Secure` iff `Scheme()` is `https`. Captcha does not read proto or TLS.

AppSec `Query` takes the same value. `X-Crowdsec-Appsec-Uri` is `AbsoluteURL()`: constructor scheme, `URL.Host` else `Request.Host`, path and query preserved. `X-Crowdsec-Appsec-Host` stays `Request.Host`.

A Go httptest through the plugin forges proto and TLS and asserts `Secure` on `crowdsec_captcha_gate` and on a stub AppSec `__crowdsec_challenge` when the forwarded URI scheme is `https`.

## What this changes
**Operators.** `X-Crowdsec-Appsec-Uri` sent to CrowdSec is an absolute URL (scheme, host, path and query), not origin-form.
**Admin users.** None.
**Developers.** Captcha `ServeHTTP`, `Check`, and `Validate`, and AppSec `Query`, take `clientrequest.Request` instead of `*http.Request` plus a parallel IP; scheme is constructor-owned (`New`, `Scheme()`, `AbsoluteURL()`).
**End users.** `crowdsec_captcha_gate` and `__crowdsec_challenge` set `Secure` when the client-facing scheme is `https`, and omit it when the scheme is `http` (including explicit proto `http` with TLS).

## Merge readiness
In progress. 0 items remain.

Priority: P2 — HTTPS clients get the AppSec challenge cookie without Secure, limited to bot-detection and that cookie
Reviewed head: f89768a9
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Not ready |
| CI proof | 1/6 | not seen |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | N/A | no OPEN PR |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-30-origin-scheme pushed | `git` |
| OpenSpec | origin-scheme | `openspec/` |
| Pull request | none | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_appsec_client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-30-origin-scheme/openspec/changes/archive/2026-09-30-origin-scheme/proposal.md) — modified
- [core_plugin_clientrequest_inbound-request](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-30-origin-scheme/openspec/changes/archive/2026-09-30-origin-scheme/proposal.md) — added
- [core_plugin_middleware_captcha-gate](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-30-origin-scheme/openspec/changes/archive/2026-09-30-origin-scheme/proposal.md) — modified

Completed:
- [core_plugin_appsec_client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-30-origin-scheme/openspec/specs/core_plugin_appsec_client/spec.md) — modified
- [core_plugin_clientrequest_inbound-request](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-30-origin-scheme/openspec/specs/core_plugin_clientrequest_inbound-request/spec.md) — added
- [core_plugin_middleware_captcha-gate](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-30-origin-scheme/openspec/specs/core_plugin_middleware_captcha-gate/spec.md) — modified


## Deviations from the ask
- taken: one real end-to-end test forges TLS on/off and `X-Forwarded-Proto` and asserts Secure on `crowdsec_captcha_gate` and `__crowdsec_challenge`. → one Go httptest through the plugin with a stub AppSec that sets `__crowdsec_challenge` Secure iff the forwarded URI scheme is `https`. — `pkg/bouncer httptest (zzz_bouncer_test.go testBouncerWithAppsec) and pkg/captcha gate tests` — honouring "real" would add an HTTPS Traefik entrypoint to compose that is HTTP `:80` only; mocklapi does not implement CrowdSec's scheme check. The job (both cookies' Secure under TLS and proto) survives on the existing plugin test harness.. Requester: not asked.


## Follow-up issues
None.

## How this fits together
Ticket 2026-09-30-origin-scheme on branch 2026-09-30-origin-scheme targeting master; PR no PR yet; CI not seen.

## Explore Decisions
None.

## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-30-origin-scheme/devstate/2026/09/2026-09-30-origin-scheme/codereview_standards.md) — 0 total, 0 pending, 0 completed
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-30-origin-scheme/devstate/2026/09/2026-09-30-origin-scheme/codereview_nitpicks.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-30-origin-scheme/devstate/2026/09/2026-09-30-origin-scheme/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-30-origin-scheme/devstate/2026/09/2026-09-30-origin-scheme/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-30-origin-scheme/devstate/2026/09/2026-09-30-origin-scheme/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-30-origin-scheme/devstate/2026/09/2026-09-30-origin-scheme/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-30-origin-scheme/devstate/2026/09/2026-09-30-origin-scheme/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-30-origin-scheme/devstate/2026/09/2026-09-30-origin-scheme/codereview_coverage.md) — 0 total, 0 pending, 0 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 2 added / 4 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | f89768a96072ea62da56c1484373a37344a3a1b5 | Card must match the branch you measured |

### Stored data model
None.
