Developer review: in progress — 2026-09-18T14:56:35Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None.

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
Explore is done; product apply has not started. 3 items remain.

Priority: P2 — real operator and test pain (file-in-use plus extra descriptor) when `logFilePath` is set, limited blast radius.
Reviewed head: 9e08331
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | CI queued on the explore head; no apply yet |
| CI proof | 3/6 | Main Process and Race detector queued https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35359309660 |
| Local tests proof | N/A | Before implement (`localTests: none`) |
| Review resolution | 6/6 | OPEN PR, no review comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-18-validateparams-logfile-fd-leak pushed | git |
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/95 | pr-host List |
| CI | build 35359309660 queued https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35359309660 | GitHub check runs |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | no comments.md |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local dump → branch `2026-09-18-validateparams-logfile-fd-leak` → stub PR #95 → explore.md on `9e08331`. Product fix is not in this head.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| How does the test prove the handle is closed on Linux CI, where `Remove` can succeed while the file is still open? | assumed — Windows `Remove` after successful `ValidateParams` is the hunt proof (measured file-in-use on this host). On Linux, after `ValidateParams` scan `/proc/self/fd` and assert no descriptor still names the temp path. Skip the leak assertion only when neither Windows nor `/proc/self/fd` is available; still assert `ValidateParams` succeeds. | explore |
| What if `Close` fails after a successful open? | assumed — ignore the `Close` error; writability is already proven. Same discard as the logger `LoadOrStore` loser close. | explore |

## Before merge
- [ ] Close the writability-check file after a successful open so ValidateParams does not keep an extra descriptor
- [ ] Add `TestHunt_ValidateParams_closesLogFileAfterWritabilityCheck` in `pkg/configuration/zzz_configuration_test.go`
- [ ] Do not take logger-file-reclaim unless that close fix requires it

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
| Reviewed head | 9e08331b04c537412fe7c865ac4d9f499822b7ce | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: close the writability-check `OpenFile` after success; keep the independent hard-fail check. Dest still discards the handle.

Do we have a high-confidence way to reproduce? Yes — measured on this Windows host: `ValidateParams` then `Remove` fails file-in-use; `NewWithFormat` + `ValidateParams` + `ResetSharedLogFilesForTest` then `Remove` still fails (extra handle is the check open).

Is this the best way to solve the issue? Yes vs dest — close is smaller than reuse and keeps the constructor fail when the logger already fell back to stdout.

### Evidence
What I checked:
- `validateLogging` opens `LogFilePath` and assigns the file to `_` (`pkg/configuration/configuration.go`, `origin/master` 84a9045)
- `plugin.New` opens the same path via `logger.NewWithFormat` before `ValidateParams` (`plugin.go`)
- Throwaway probe (OS temp): control open-without-close Remove FAIL; close then Remove OK; ValidateParams then Remove FAIL; logger+ValidateParams+ResetShared then Remove FAIL
- Existing `go test ./pkg/configuration/ ./pkg/logger/` pass (they do not assert this close)
- Hunt test not on dest
- PR #95; CI run 35359309660 queued on head 9e08331

### Rank-up moves
None.

[sgsi-dev-ticket-status:2026-09-18-validateparams-logfile-fd-leak]
