## Motivation
After a visitor has already solved the CrowdSec captcha, leftover-form detection still treats a non-empty vendor token field (`g-recaptcha-response`, `h-captcha-response`, `cf-turnstile-response`, `eu-captcha-response`, or a custom TokenField) as proof that the POST is the CrowdSec challenge.

The visitor holds a valid `crowdsec_captcha_gate` cookie and submits an ordinary application form that also embeds the same vendor widget. The plugin answers `302 Found` to that same URL and does not forward the body. Browsers follow the 302 with a GET and drop the POST. A route that accepts only POST then renders its own not-found page; a refresh repeats the GET.

The leftover-tab case is real: the gate cookie is shared across tabs, and a second submit of the CrowdSec challenge must still be kept off origin. Using the vendor field as that proof is the wrong signal, so solved visitors lose application POSTs today.

Priority: P1 — production is serving a wrong public contract today

## Implementation
`IsCaptchaFormPost` still runs after `Check` is true on the captcha-kind path, but it now answers yes only when the POST carries leftover-form marker `crowdsec_captcha_challenge=v1`. It no longer reads `widget.TokenField`. The 64KiB peek, urlencoded/multipart/already-parsed readers, and first-solve `Validate`/`TokenField` path stay. `pkg/captcha` owns the marker name and value constants; the six shipped challenge pages emit the same hidden input. No Config key.

## What this changes
**Operators.** A replaced challenge template that still wants leftover-tab redirect must include hidden `crowdsec_captcha_challenge=v1`; omitting it still first-solves, and a second submit of that template is forwarded.
**Admin users.** None.
**Developers.** After `Check` is true, leftover-form detection is `crowdsec_captcha_challenge=v1` only; a non-empty provider TokenField is not leftover proof.
**End users.** After solving the captcha, an application form POST that includes a vendor token field reaches the application instead of being redirected.

## Merge readiness
Ready for review. 1 items remain.

Priority: P1 — production is serving a wrong public contract today
Reviewed head: 775cdd44
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Ready |
| CI proof | 6/6 | succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/38850093953 |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-10-16-captcha-leftover-form-marker pushed | `git` |
| OpenSpec | captcha-challenge-form-marker | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/201 | pr-host |
| CI | build 38850093953 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/38850093953 | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/38850093953 |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_middleware_captcha-routing](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-16-captcha-leftover-form-marker/openspec/changes/captcha-challenge-form-marker/proposal.md) — modified
- [core_plugin_middleware_captcha-widget](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-16-captcha-leftover-form-marker/openspec/changes/captcha-challenge-form-marker/proposal.md) — modified


## Deviations from the ask
- taken: leftover detection is POST contains `crowdsec_captcha_challenge=v1`, with no size named. → leftover detection keeps the existing 64KiB peek; over-cap bodies are not leftover forms. — `pkg/captcha/form.go (captchaFormMaxBytes, peekCaptchaFormBody)` — honouring an uncapped read would drop the live routing promise that detection never costs origin its body; the ask's HTML does not name dropping the cap.. Requester: not asked.


## Follow-up issues
- [ ] [Tighten Debounced status-code assertion](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-16-captcha-leftover-form-marker/knowledge/debt/2026-10-16-logger-debounce-status-substring.md) — TestDebounced_sameMessageOnce matches statusCode 502 via Contains("502"), so a timestamp millisecond .502 fails it.


## How this fits together
Ticket 2026-10-16-captcha-leftover-form-marker on branch 2026-10-16-captcha-leftover-form-marker targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/201; CI build 38850093953 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/38850093953.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| After the gate is valid, does leftover-form detection read only crowdsec_captcha_challenge=v1, not TokenField? | bounded asked — existing IsCaptchaFormPost has 1 production caller in pkg/bouncer/bouncer.go handleCaptchaKindServeHTTP, searched Go files; requirement Proposed solution valid-gate branch names marker-only detection | assumed — change IsCaptchaFormPost to that marker; migrate the bouncer caller (signature stays) and the routing tests in pkg/captcha and pkg/bouncer. | explore |


## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-16-captcha-leftover-form-marker/devstate/staging/2026/10/2026-10-16-captcha-leftover-form-marker/codereview_standards.md) — 0 total, 0 pending, 0 completed
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-16-captcha-leftover-form-marker/devstate/staging/2026/10/2026-10-16-captcha-leftover-form-marker/codereview_nitpicks.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-16-captcha-leftover-form-marker/devstate/staging/2026/10/2026-10-16-captcha-leftover-form-marker/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-16-captcha-leftover-form-marker/devstate/staging/2026/10/2026-10-16-captcha-leftover-form-marker/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-16-captcha-leftover-form-marker/devstate/staging/2026/10/2026-10-16-captcha-leftover-form-marker/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-16-captcha-leftover-form-marker/devstate/staging/2026/10/2026-10-16-captcha-leftover-form-marker/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-16-captcha-leftover-form-marker/devstate/staging/2026/10/2026-10-16-captcha-leftover-form-marker/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-16-captcha-leftover-form-marker/devstate/staging/2026/10/2026-10-16-captcha-leftover-form-marker/codereview_coverage.md) — 0 total, 0 pending, 0 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 2 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 775cdd44397fbd3b34a8781f61757d6e554ce224 | Card must match the branch you measured |

### Stored data model
None.
