Developer review: needs changes — 2026-09-18T17:01:29Z

## What this changes
**Operators.** Leftover invalid AppSec CA or a missing `crowdsecAppsecKeyFile` no longer fail `ValidateParams` when `crowdsecAppsecEnabled` is false. Alone with AppSec on and those same leftovers now fails closed at startup.

**Admin users.** None.

**Developers.** `ValidateParams` calls `validateAppsecURLKeyAndTLS` only when `CrowdsecAppsecEnabled` is true, in every mode. Alone still skips LAPI URL, key, and TLS after CAPI credentials. The `validateLapiAndAppsecConnection` wrapper is gone. Catalog spec `core_plugin_middleware_config-validation` now owns the enabled-gate requirements.

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
CI on head `6ae4b30` failed. 1 item remains.

Priority: P2 — real operator pain, with a workaround or limited blast radius
Reviewed head: 6ae4b30
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 2/6 | e2e (binary + mock LAPI) failed |
| CI proof | 2/6 | One required check failed |
| Local tests proof | N/A | Remote PR; CI proof covers this |
| Review resolution | 6/6 | OPEN PR #97; no reviewer comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-18-appsec-validate-when-enabled pushed | `git` `origin/2026-09-18-appsec-validate-when-enabled` at `6ae4b30` |
| OpenSpec | appsec-validate-when-enabled | `openspec/changes/archive/2026-09-18-appsec-validate-when-enabled/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/97 | pr-host List |
| CI | Race detector success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35371432958/job/105686078515 ; Main Process success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35371432958/job/105686078862 ; e2e (binary + mock LAPI) failure https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35371433064/job/105686080001 ; e2e (docker + pester) success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35371433064/job/105686079696 | pr-host CI |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | no `comments.md` |

## Specs
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-18-appsec-validate-when-enabled/openspec/changes/archive/2026-09-18-appsec-validate-when-enabled/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
Local ticket `2026-09-18-appsec-validate-when-enabled` on branch `2026-09-18-appsec-validate-when-enabled` as PR #97. Pullrequest reused that stub and dropped WIP. CI on `f0ea972` succeeded; CI on card-commit `6ae4b30` failed e2e (binary + mock LAPI).

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Do none and appsec modes share the same enabled gate even though the required test list names live/stream/alone? | assumed — yes, all modes. Do not add empty-host (#89) cases. A leftover-CA success under `crowdsecMode: appsec` with AppSec off is allowed if cheap; the existing warn test stays. | propose |
| Should AppSec CA parse use `effectiveAppsecScheme` (inherit LAPI `https`) instead of explicit `CrowdsecAppsecScheme == https`? | assumed — keep today’s explicit-scheme trigger. Changing inherit-https CA parse would rewrite live/stream validation and is out of scope. | propose |
| When AppSec is enabled and the key is empty, should `ValidateParams` fail? | assumed — no. Keep the helper’s empty-key pass; `appsec.Prepare` still copies the LAPI key. This ticket only adds the enabled gate around the existing helper. | propose |
| Should leftover `CrowdsecAppsecFailureAction` / body-limit checks also skip when AppSec is off (Redis leftover-password analog)? | assumed — leave them. Failure-action behavior is out of scope. Dest still always `GetVariable`s `RedisCachePassword`; do not change Redis in this ticket. | propose |
| Does this change `appsec.Prepare`, reclaim, or `New` process lifetime? | assumed — no. `ValidateParams` is the constructor gate. Runtime AppSec client, reclaim, and failure-action stay out. | propose |
| Should leftover AppSec fields warn when the knob is false? | assumed — no. Ticket is skip validation, not a new warn. Bound the ask. | propose |

## Before merge
- [ ] [P2] e2e (binary + mock LAPI) failed on `6ae4b30` — https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35371433064/job/105686080001

## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-18-appsec-validate-when-enabled/devstate/2026/09/2026-09-18-appsec-validate-when-enabled/codereview_standards.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-18-appsec-validate-when-enabled/devstate/2026/09/2026-09-18-appsec-validate-when-enabled/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-18-appsec-validate-when-enabled/devstate/2026/09/2026-09-18-appsec-validate-when-enabled/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-18-appsec-validate-when-enabled/devstate/2026/09/2026-09-18-appsec-validate-when-enabled/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-18-appsec-validate-when-enabled/devstate/2026/09/2026-09-18-appsec-validate-when-enabled/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-18-appsec-validate-when-enabled/devstate/2026/09/2026-09-18-appsec-validate-when-enabled/codereview_coverage.md) — 0 total, 0 pending, 0 completed

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 1 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 6ae4b30bc9cddc3a12b0f1b79cd4e4d4978e04d9 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: gate `validateAppsecURLKeyAndTLS` on `CrowdsecAppsecEnabled` in every mode; do not reuse declined PR #80’s always-on AppSec checks in alone.

Do we have a high-confidence way to reproduce? Yes — `Test_ValidateParams` leftover-CA and missing-key cases now pass when AppSec is off and fail when it is on (`go test ./pkg/configuration/`).

Is this the best way to solve the issue? Yes versus DestBranch — reuse the existing helper behind the enabled knob; do not invent a second signal or restore PR #80.

### Evidence
What I checked:
- Pin `origin/master` (`86ac9266`) three-dot product diff excluding `devstate/` and `.cursor/`
- Sync: `origin/master` already merged
- OPEN PR #97 reused; title set to ready gitmoji form (pr-host Update)
- Comment inventory empty; no `comments.md` (file on disk)
- CI on `f0ea972`: four checks success (pr-host check runs)
- CI on `6ae4b30`: e2e (binary + mock LAPI) failure exit 2, mock captcha logs annotated; other three checks success

### Rank-up moves
None.
