Developer review: in progress — 2026-09-18T16:14:53Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** Explore recorded the enabled-gate decisions on this ticket. Versus `master`, live/stream still always run AppSec URL/key/CA checks; alone still skips that helper after CAPI credentials.

**End users.** None.

## Motivation
`ValidateParams` decides whether leftover AppSec URL, key-file, and HTTPS CA knobs can stop a router from booting. Dest splits that by mode: live and stream always run those AppSec checks; alone skips the whole LAPI+AppSec helper after CAPI machine id and password.

On `master`, a live or stream router with `crowdsecAppsecEnabled` false still fails when `crowdsecAppsecKeyFile` is missing or `crowdsecAppsecScheme` is explicit `https` with a garbage CA. Alone with AppSec on and those same leftovers boots. Default AppSec failure action is ban, so later requests on that router drop.

Not merging leaves two operator failures: unused AppSec fields in a shared snippet block boot, and an AppSec-on alone router with a bad CA or missing key file does not fail at startup.

```mermaid
flowchart TD
  VP[ValidateParams]
  VP -->|alone| CAPI[CAPI machine id and password]
  CAPI --> Skip[Skip LAPI and AppSec checks]
  Skip --> Boot[Boot]
  VP -->|live stream none appsec| LAPI[Validate LAPI]
  LAPI --> Always[Always validate AppSec URL key CA]
  Always -->|leftover missing key or garbage CA| Fail[Fail even if AppSec is off]
  Always -->|fields valid| Boot2[Boot]
```

## Merge readiness
Explore is written. The enabled gate is not on this branch yet. 2 items remain.

Priority: P2 — real operator pain, with a workaround or limited blast radius
Reviewed head: 7c060e7
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | CI in progress; no product gate yet |
| CI proof | 3/6 | All measured checks in progress |
| Local tests proof | N/A | Before implement; remote PR uses CI |
| Review resolution | 6/6 | OPEN PR #97; no reviewer comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-18-appsec-validate-when-enabled pushed | `git` `origin/2026-09-18-appsec-validate-when-enabled` at `7c060e7` |
| OpenSpec | none | `openspec/` unchanged vs `master` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/97 | pr-host List |
| CI | e2e (binary + mock LAPI) in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35367283269/job/105672677127 ; e2e (docker + pester) in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35367283269/job/105672677493 ; Race detector in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35367283296/job/105672677937 ; Main Process in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35367283296/job/105672677858 | pr-host CI |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | no `comments.md` |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local ticket `2026-09-18-appsec-validate-when-enabled` on branch `2026-09-18-appsec-validate-when-enabled` as PR #97. Explore wrote `explore.md`; product still matches `master`.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Do none and appsec modes share the same enabled gate even though the required test list names live/stream/alone? | assumed — yes, all modes. Do not add empty-host (#89) cases. A leftover-CA success under `crowdsecMode: appsec` with AppSec off is allowed if cheap; the existing warn test stays. | explore |
| Should AppSec CA parse use `effectiveAppsecScheme` (inherit LAPI `https`) instead of explicit `CrowdsecAppsecScheme == https`? | assumed — keep today’s explicit-scheme trigger. Changing inherit-https CA parse would rewrite live/stream validation and is out of scope. | explore |
| When AppSec is enabled and the key is empty, should `ValidateParams` fail? | assumed — no. Keep the helper’s empty-key pass; `appsec.Prepare` still copies the LAPI key. This ticket only adds the enabled gate around the existing helper. | explore |
| Should leftover `CrowdsecAppsecFailureAction` / body-limit checks also skip when AppSec is off (Redis leftover-password analog)? | assumed — leave them. Failure-action behavior is out of scope. Dest still always `GetVariable`s `RedisCachePassword`; do not change Redis in this ticket. | explore |
| Does this change `appsec.Prepare`, reclaim, or `New` process lifetime? | assumed — no. `ValidateParams` is the constructor gate. Runtime AppSec client, reclaim, and failure-action stay out. | explore |
| Should leftover AppSec fields warn when the knob is false? | assumed — no. Ticket is skip validation, not a new warn. Bound the ask. | explore |

## Before merge
- [ ] [P2] Gate `validateAppsecURLKeyAndTLS` on `crowdsecAppsecEnabled` in every mode; keep alone skipping LAPI URL/key/TLS.
- [ ] [P2] Add the four mode/enabled leftover-CA and missing-key-file cases; update dest tests and specs that assume live/stream always validate AppSec when off.

## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 7c060e72f6a77d5f2c7e30032effcba4f3aab7fd | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: gate `validateAppsecURLKeyAndTLS` on `CrowdsecAppsecEnabled` in every mode; do not reuse declined PR #80’s always-on AppSec checks in alone.

Do we have a high-confidence way to reproduce? Yes — dest `Test_ValidateParams` case "AppSec HTTPS with invalid CA while LAPI HTTP" still fails with AppSec off (`go test ./pkg/configuration`); alone + AppSec on + garbage CA is missing and would pass today.

Is this the best way to solve the issue? Yes versus DestBranch — reuse the existing helper behind the enabled knob; do not invent a second signal or restore PR #80.

### Evidence
What I checked:
- `origin/master...HEAD` product delta empty (`git diff` excluding `devstate/` and `.cursor/`)
- Dest leftover-CA table case still fails with AppSec off (`go test ./pkg/configuration -run Test_ValidateParams/AppSec_HTTPS_with_invalid_CA_while_LAPI_HTTP`)
- OPEN PR #97; comment inventory empty (pr-host List)
- CI on head `7c060e7`: four checks in progress (pr-host check runs)

### Rank-up moves
None.
