Developer review: ready for review — 2026-09-18T18:20:07Z

## What this changes
**Operators.** Optional `captchaCustomValidateBody`: omit/`form` keeps today’s urlencoded siteverify; `json` (custom only) POSTs `application/json` `{"secret","response"}`. CapJS example: `captchaCustomValidateUrl` + `captchaCustomResponse: cap-token` + `json`.

**Admin users.** None.

**Developers.** `CaptchaCustomValidateBody` is validated in `validateCaptcha` and stored on `captcha.Client` (sibling of `challengeURL`). Custom+`json` uses `postSiteverify` JSON; form/omit and built-ins stay `PostForm`. Dest `Validate(r)` still has no address, so no `remoteip`. Specs folded on `core_plugin_middleware_captcha-siteverify` and `core_plugin_middleware_config-validation`.

**End users.** A custom CapJS solve that dest re-challenged can now pass: 302 plus `crowdsec_captcha_gate` when the operator sets `json`.

## Motivation
Custom captcha already lets an operator name the browser token field and the siteverify URL. Dest always posts that second hop as urlencoded `secret` and `response`. Cap Standalone / CapJS documents the same two fields as a JSON object with `Content-Type: application/json`.

On dest, a custom provider pointed at a CapJS `/<site_key>/siteverify` URL still sends `PostForm`. The provider does not see JSON, so `success` stays false, the gate cookie is not minted, and the client is re-shown the challenge. Form-compatible custom providers (Wicketkeeper) keep working because omit/form is today’s path.

Without the knob, CapJS custom stays unusable on this plugin.

```mermaid
sequenceDiagram
  participant Browser
  participant Validate as Validate
  participant CapJS
  Browser->>Validate: POST cap-token
  Validate->>CapJS: PostForm secret+response
  Note over CapJS: wants application/json
  CapJS-->>Validate: not a JSON success
  Validate-->>Browser: challenge HTML again
```

## Merge readiness
Implement landed on d7d7602 and CI succeeded. 0 items remain.

Priority: P2 — CapJS custom siteverify fails on dest while form providers still work
Reviewed head: d7d7602
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | CI succeeded; no open PR comments |
| CI proof | 6/6 | all required checks succeeded on d7d7602 |
| Local tests proof | N/A | `prHost` remote; CI proof covers it (`localTests: passed`) |
| Review resolution | 6/6 | OPEN PR #105; no review comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-18-captcha-custom-json-verify pushed | `git` / origin |
| OpenSpec | captcha-custom-validate-body | `openspec/changes/captcha-custom-validate-body/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/105 | pr-host List |
| CI | Main Process success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35379014285/job/105710474593 ; Race detector success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35379014285/job/105710473611 ; e2e (binary + mock LAPI) success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35379014280/job/105710593209 ; e2e (docker + pester) success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35379014280/job/105710593509 | GitHub check runs |
| Local tests | passed | handoff.yaml localTests; `go test ./...` |
| PR comments | no comments | no comments.md; Comment-List empty |

## Specs
- [core_plugin_middleware_captcha-siteverify](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-18-captcha-custom-json-verify/openspec/changes/captcha-custom-validate-body/proposal.md) — modified
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-18-captcha-custom-json-verify/openspec/changes/captcha-custom-validate-body/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
Local ticket → branch `2026-09-18-captcha-custom-json-verify` from `origin/master` → stub PR #105 → OpenSpec `captcha-custom-validate-body` applied → CI green on d7d7602.

## Decision needed
None.

## Before merge
- [x] Implement `captchaCustomValidateBody` (`""`/`form` vs `json`) for custom only, with tests and a CapJS README example
- [x] OpenSpec change `captcha-custom-validate-body` apply-ready
- [x] Stub PR #105 opened
- [x] CI succeeded on d7d7602

## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 2 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | d7d76027cc01d5f75e58a933d2ed2e17c97a09d9 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: custom-only `captchaCustomValidateBody` (`""`/`form` keep dest `PostForm`; `json` POSTs official Cap JSON) versus dest `PostForm`-only `Validate`.

Do we have a high-confidence way to reproduce? Yes — httptest custom+json sees `application/json` `secret`/`response`; dest `Validate(r)` omits `remoteip`.

Is this the best way to solve the issue? Yes — a custom-only encoding knob keeps Wicketkeeper form default and avoids a `trycap` provider.

### Evidence
What I checked:
- dest after Sync still `Validate(r)` only; no `remoteip` invented (`pkg/captcha/captcha.go`, origin/master merge already up to date)
- `go test ./...` passed; golangci-lint on configuration/captcha/bouncer passed
- CI on d7d7602: Main Process, Race detector, e2e mock, e2e docker all success
- PR #105 Comment-List empty

### Rank-up moves
None.
