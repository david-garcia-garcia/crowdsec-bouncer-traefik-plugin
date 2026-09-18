# Code review — Test coverage

Every defect was measured red on `87d1084` before the fix, then green after.

| Deliverable | Test | Red before | Green after |
|---|---|---|---|
| 1 rollback | `TestNew_FailedConstructorReleasesLapiHolder` | `failed New left a stream ticker running: 2 further LAPI polls` | pass (0 polls) |
| 1 success path | `TestNew_SuccessfulConstructorKeepsItsHolder` | n/a (guard against over-releasing) | pass |
| 2 warning | `TestValidateParams_AppsecModeWithoutAppsecWarns` | `appsec mode with AppSec disabled must warn` | pass |
| 2 warning is specific | `TestValidateParams_AppsecModeWithAppsecIsSilent` | n/a (guard) | pass |
| 2 operator-visible | `TestNew_AppsecModeWithoutAppsecWarns` | `no WARN line for appsec mode without AppSec` | pass |
| 3 README | none — documentation | n/a | n/a |
| 4 appsec captcha | `TestNew_AppsecModeCaptchaFailureActionServesChallenge` | `remediation "ban" want captcha` | pass |
| 5 snapshot | `TestNew_DoesNotMutateCallerConfig` | `New normalised the caller's logLevel to "INFO"` | pass |

- [x] V1 Deliverable 1 is proven by observable effect (LAPI polls stop), not by inspecting table
  internals, so it survives a reclaim-table refactor.
  Status: pass.
- [x] V2 Deliverable 4 is proven end to end through `plugin.New`, the path the ticket reproduced on,
  rather than by hand-building a `Bouncer` literal.
  Status: pass.
- [x] V3 Deliverable 5 needed no test change outside the constructor, which is the ticket's own
  criterion for keeping it.
  Status: pass. Argument: the edit is wider than #22's three lines because every `config.` inside
  `New` became `prepared.`, but no existing test moved and no caller changed.
- [x] V4 #33's 419-line `servehttp_test.go` was not ported.
  Status: pass. Argument: its `testValidCaptchaClient(t, cacheClient)` helper cannot compile against
  master's stateless captcha client, and `pkg/bouncer` already has ~28 tests over these paths. One
  test at the level the defect was reproduced is the bar the ticket set.
- [ ] V5 Real-stack Pester e2e coverage of appsec-mode captcha.
  Status: not taken. Argument: the suite cannot run locally (hard-coded ports 8000/8080/8081 and
  subnet `172.20.0.0/16` collide with the owner's dev stack) and is independently flaky at startup.
  CI on the pushed head is the measurement: `e2e (docker + pester)` succeeded on `77730df`
  (run 35351880057), as did `e2e (binary + mock LAPI)`, `Race detector` and `Main Process`.
