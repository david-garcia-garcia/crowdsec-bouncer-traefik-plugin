Developer review: in progress — 2026-09-06T15:14:56Z

IssueKey: 2026-09-06-upstream-380-trycap-captcha
JobName: 2026-09-06-upstream-380-trycap-captcha

[sgsi-dev-ticket-status:2026-09-06-upstream-380-trycap-captcha]

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** OpenSpec change `trycap-captcha-provider` and new spec `core_plugin_captcha_trycap-provider` (plus Cap Standalone research and Captcha Client usage packet). Plugin code is still unchanged.

**End users.** None.

## Motivation
On `master`, operators who self-host TryCap Cap Standalone cannot select it as a built-in captcha provider. The plugin only verifies captchas via urlencoded `PostForm`, while Cap Standalone expects JSON `{"secret","response"}` at `/<site_key>/siteverify` with a `cap-token` field — so TryCap fails unless the operator runs an external adapter. Without this change, self-hosted TryCap remains unsupported despite upstream feature request #380.

## Merge readiness
Propose complete; implement is next. Product apply and tests remain.

Priority: P2 — real operator pain with a workaround (external adapter or misconfigured custom provider).
Reviewed head: 87930ae
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | CI still running; no product apply yet |
| CI proof | 3/6 | e2e in progress; Main Process queued |
| Local tests proof | N/A | Before implement |
| Review resolution | 6/6 | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-upstream-380-trycap-captcha pushed | git / GitHub |
| OpenSpec | trycap-captcha-provider | openspec/changes/trycap-captcha-provider/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/40 | pr-host |
| CI | build 34041580794 queued / 34041580787 in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041580787 | pull_request_read get_check_runs |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | comments.md absent |

## Specs
- [core_plugin_captcha_trycap-provider](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-380-trycap-captcha/openspec/changes/trycap-captcha-provider/proposal.md) — added

## Follow-up issues
- [ ] [note] [large] custom provider JSON siteverify (upstream #318) — TryCap needs JSON; `custom` still PostForms. Not taken: out of scope for this change.

## How this fits together
Local ticket (upstream #380) → branch `2026-09-06-upstream-380-trycap-captcha` → stub PR #40 → explore decisions → OpenSpec `trycap-captcha-provider` proposed → implement next.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| What is the official product name for the provider enum and docs — TryCap, Cap, or Cap Standalone? | assumed — enum `trycap`; README says Cap Standalone (trycap.dev) and key `captchaTrycapInstanceUrl` | explore |
| Where does the widget JavaScript load from — the instance or a CDN? | assumed — jsDelivr `cap-widget` as `type="module"`; instance URL is API only | explore |
| Does instance URL belong in a dedicated config key or reuse CaptchaCustomValidateURL? | assumed — dedicated `captchaTrycapInstanceUrl` | explore |
| Can default captcha.html serve all providers, or does TryCap need a separate template? | assumed — one default template with a Cap widget branch | explore |
| Does Cap siteverify accept recaptcha-style form-urlencoded, so PostForm would work? | assumed — no; documented contract is JSON | explore |
| Should this change also make `custom` POST JSON (upstream #318 CapJS)? | assumed — no; note as follow-up | explore |
| Must CI e2e run a live `tiago2/cap` container? | assumed — no; unit tests prove verify | explore |

## Before merge
- [ ] Add `trycap` provider, JSON siteverify, default-template Cap branch, and unit tests

## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 1 added / 0 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 87930ae384887ff122cce8c6f8ce62f12000e487 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: First-class `trycap` with derived instance URLs and JSON verify, without changing `custom`.

Do we have a high-confidence way to reproduce? Yes, `pkg/captcha.Validate` always `PostForm`s; Cap docs require JSON.

Is this the best way to solve the issue? Yes — a built-in matches hcaptcha/recaptcha/turnstile; `custom` cannot speak JSON.

### Evidence
What I checked:
- OpenSpec `openspec/changes/trycap-captcha-provider/` apply-ready (`openspec status` isComplete)
- FindSpecHost: new `core_plugin_captcha_trycap-provider` (no existing captcha leaf)
- PR #40 checks in progress (runs 34041580787 / 34041580794)

### Rank-up moves
None.
