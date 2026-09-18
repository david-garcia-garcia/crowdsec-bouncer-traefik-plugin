Developer review: ready for review — 2026-09-18T15:12:47Z

## What this changes
**Operators.** A successful start with `logFilePath` set no longer keeps a leftover check handle on that file.

**Admin users.** None.

**Developers.** `validateLogging` closes the writability-check `OpenFile` after success; `TestHunt_ValidateParams_closesLogFileAfterWritabilityCheck` proves the handle is gone and an unwritable path still fails.

**End users.** None.

## Motivation
On master, startup checks that `logFilePath` is writable by opening the file and dropping the handle. The constructor already opened that same path for the slog logger. After a successful start the check handle stays open, so on Windows a later `Remove` of that path fails file-in-use.

If we do not merge, every successful `ValidateParams` with a log file retains an extra descriptor besides the logger's, and operators or tests cannot delete or replace that file while the process holds it.

```mermaid
sequenceDiagram
  participant New as plugin.New
  participant Logger as logger.NewWithFormat
  participant Check as validateLogging
  participant Disk as LogFilePath
  New->>Logger: open shared file
  Logger->>Disk: OpenFile held
  New->>Check: ValidateParams
  Check->>Disk: OpenFile discarded
  Note over Disk: two handles; Windows Remove fails
```

## Merge readiness
Apply is on the branch and CI succeeded. 0 items remain.

Priority: P2 — real operator and test pain (file-in-use plus extra descriptor) when `logFilePath` is set, limited blast radius.
Reviewed head: 44e1cfc
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Apply landed; required checks succeeded; no open review comments |
| CI proof | 6/6 | Main Process, Race detector, e2e (binary + mock LAPI), and e2e (docker + pester) succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35360397039 |
| Local tests proof | N/A | `prHost` remote (CI proof covers remote); handoff `localTests: passed` |
| Review resolution | 6/6 | OPEN PR, no review comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-18-validateparams-logfile-fd-leak pushed | git |
| OpenSpec | close-validateparams-logfile-check-handle | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/95 | pr-host List |
| CI | Main Process success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35360397039/job/105649943411 ; Race detector success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35360397039/job/105649943547 ; e2e (binary + mock LAPI) success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35360397038/job/105650020216 ; e2e (docker + pester) success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35360397038/job/105650020676 | GitHub check runs |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | no comments.md |

## Specs
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-18-validateparams-logfile-fd-leak/openspec/changes/close-validateparams-logfile-check-handle/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
Local dump → branch `2026-09-18-validateparams-logfile-fd-leak` → stub PR #95 → apply `44e1cfc` → CI succeeded.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| How does the test prove the handle is closed on Linux CI, where `Remove` can succeed while the file is still open? | assumed — Windows `Remove` after successful `ValidateParams` is the hunt proof (measured file-in-use on this host). On Linux, after `ValidateParams` scan `/proc/self/fd` and assert no descriptor still names the temp path. Skip the leak assertion only when neither Windows nor `/proc/self/fd` is available; still assert `ValidateParams` succeeds. | explore |
| What if `Close` fails after a successful open? | assumed — ignore the `Close` error; writability is already proven. Same discard as the logger `LoadOrStore` loser close. | explore |

## Before merge
- [x] Close the writability-check file after a successful open so ValidateParams does not keep an extra descriptor
- [x] Add `TestHunt_ValidateParams_closesLogFileAfterWritabilityCheck` in `pkg/configuration/zzz_configuration_test.go`
- [x] Do not take logger-file-reclaim (close landed without it)

## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 1 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 44e1cfcd2ad057195a3d5646029b51f5dca5fd60 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: close the writability-check `OpenFile` after success; keep the independent hard-fail check. Dest still discards the handle.

Do we have a high-confidence way to reproduce? Yes — measured on this Windows host: dest `ValidateParams` then `Remove` fails file-in-use; after apply the hunt test `Remove`s the temp path.

Is this the best way to solve the issue? Yes vs dest — close is smaller than reuse and keeps the constructor fail when the logger already fell back to stdout.

### Evidence
What I checked:
- `validateLogging` closes `checkFile` after a successful `OpenFile` (`pkg/configuration/configuration.go`, `44e1cfc`)
- Hunt test `TestHunt_ValidateParams_closesLogFileAfterWritabilityCheck` in `pkg/configuration/zzz_configuration_test.go`
- Local `go test ./pkg/configuration/` and `go test ./...` passed
- PR #95; Main Process success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35360397039/job/105649943411 ; Race detector success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35360397039/job/105649943547 ; e2e (binary + mock LAPI) success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35360397038/job/105650020216 ; e2e (docker + pester) success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35360397038/job/105650020676

### Rank-up moves
None.

[sgsi-dev-ticket-status:2026-09-18-validateparams-logfile-fd-leak]
