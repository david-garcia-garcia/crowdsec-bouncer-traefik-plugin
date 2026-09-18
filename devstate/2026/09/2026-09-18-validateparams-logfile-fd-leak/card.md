Developer review: in progress — 2026-09-18T14:51:38Z

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
Prepare is done; product apply has not started. 4 items remain.

Priority: P2 — real operator and test pain (file-in-use plus extra descriptor) when `logFilePath` is set, limited blast radius.
Reviewed head: 185ef4a
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | CI still in progress; no apply yet |
| CI proof | 3/6 | Main Process in progress; other jobs queued https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35358805790/job/105644658638 |
| Local tests proof | N/A | Before implement (`localTests: none`) |
| Review resolution | 6/6 | OPEN PR, no review comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-18-validateparams-logfile-fd-leak pushed | git |
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/95 | pr-host Create |
| CI | build 35358805790 in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35358805790 | GitHub check runs |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | no comments.md |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local dump → branch `2026-09-18-validateparams-logfile-fd-leak` → stub PR #95 → prepare bus on `185ef4a`. Product fix is not in this head.

## Decision needed
None.

## Before merge
- [ ] Close the writability-check file (or reuse the logger handle) so successful ValidateParams does not keep an extra descriptor
- [ ] Add a regression test that the check handle is not held (Windows Remove after successful ValidateParams)
- [ ] Do not take logger-file-reclaim unless that close-or-reuse fix requires it
- [ ] Remaining workflow phases after prepare

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
| Reviewed head | 185ef4a6bb4450030552bbe4deaabdae6f04ca88 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: not chosen yet — dest still discards the writability `OpenFile` handle.

Do we have a high-confidence way to reproduce? Yes — hunt proof `TestHunt_ValidateParams_closesLogFileAfterWritabilityCheck` (not on dest); ticket names Windows Remove file-in-use after ValidateParams.

Is this the best way to solve the issue? Not applied. Desired is close-or-reuse so ValidateParams does not retain an extra descriptor.

### Evidence
What I checked:
- `validateLogging` opens `LogFilePath` and assigns the file to `_` (`pkg/configuration/configuration.go`, `origin/master` 84a9045)
- `plugin.New` opens the same path via `logger.NewWithFormat` before `ValidateParams` (`plugin.go`)
- Hunt test not on dest (path not found)
- PR #95 opened; CI run 35358805790 in progress on head 185ef4a

### Rank-up moves
None.

[sgsi-dev-ticket-status:2026-09-18-validateparams-logfile-fd-leak]
