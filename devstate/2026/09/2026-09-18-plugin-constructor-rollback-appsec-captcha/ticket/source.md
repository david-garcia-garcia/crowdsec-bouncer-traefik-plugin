# Ticket source: roll back reclaim holders when the constructor fails, and fix the appsec-mode gaps

Scratch source for the ticket. Copy to `ticket/source.md` in the bus folder and delete this file
from the repository root.

Suggested key: `2026-09-18-plugin-constructor-rollback-appsec-captcha`.

Rebuilt from open PRs **#31** and **#33**, which the owner will close in this ticket's favour, plus
three lines salvaged from **#22**, already closed. Do not merge those PRs and do not reuse their
branches: #31's branch conflicts with #22's in `plugin.go`, #33's branch no longer compiles against
master's captcha client, and both bases are 24-25 commits behind. Take the *intent* below and
implement it against current `master`.

Every defect here was reproduced on `master` `87d1084` by a verification pass. You should re-prove each
one with a test that fails before your fix, but you are not starting from a cold read.

## Deliverable 1 — a failed constructor must release what it already opened

`pkg/reclaim` is now a shim over the shared utilities table, and that table releases a holder only when
the bound context is Done (`vendor/.../reclaim/table.go:493-524`). `New` binds Traefik's own long-lived
context, so when a later constructor step fails, an already-opened LAPI client is **never** released.

Reproduced: stream mode with a one-second interval plus an AppSec client certificate that fails
`tls.X509KeyPair`, so `appsec.Open` errors after `OpenStream` already succeeded. `New` returns an
error, the reclaim slot stays held, and the stream ticker keeps polling LAPI — twice more within 2.5
seconds in the test, and for the process lifetime in production.

Take #31's approach: derive a bind context inside `New`, and on any error path release the holders
opened so far. Notes from the verification pass, worth honouring:

- Keep the named-`err` defer. Do not revert to a closure-captured bool.
- **Do not cancel the bind context on the success path.**
- `bindCtx` must stay a child of the constructor context, so cancelling Traefik's context still
  releases the holder. `core_plugin_middleware_bouncer` says `New` "uses the constructor ctx as the
  AppSec reclaim holder" — that sentence should be updated to name the derived bind context, otherwise
  a strict reader will think this change violates it. `std_go_reclaim_context-lease` only requires that
  `Open` bind *a* context, so it does not block this.

## Deliverable 2 — warn, do not crash, when `appsec` mode has AppSec disabled

`ValidateParams` accepts `lapiMode: appsec` without requiring `appsecEnabled`
(`pkg/configuration/configuration.go:623`). `plugin.go:59` then skips both `OpenStream` and `OpenLive`,
`plugin.go:70` opens no AppSec client, and `bouncer.ServeHTTP:182` routes straight to
`handleNextServeHTTP`, which with `appsecEnabled` false just calls `next`. Reproduced: `New` succeeds
and the request returns 200 with no CrowdSec enforcement of any kind.

**The owner has decided: log a loud warning and keep starting. Do not reject the config.** His
reasoning is that the plugin doing nothing is not worth refusing to boot over.

Do not "fix" this by implying AppSec on. That was considered and rejected for a concrete reason:
`AppsecHost` defaults to `crowdsec:7422` (`configuration.go:174`), so implying enabled would
silently point at a host that may not exist, and with `BouncerAppsecFailureAction` defaulting to `ban`
an unreachable listener bans every request on that router. Turning a do-nothing config into a
ban-everything config on upgrade is the worst available outcome.

The warning must be findable in a log the operator actually reads, and must say plainly that the
middleware will not enforce anything in this state.

## Deliverable 3 — make the two configuration axes explicit in the README

The owner asked for this directly, because the relationship is currently something a reader has to
infer from code. `README.md:64-72` already lists the five modes, and its `appsec` row is accurate as
far as it goes, but nothing states that the mode and the AppSec toggle are **independent axes**:

- `lapiMode` selects **where decisions come from**: `none` queries LAPI on every request, `live`
  queries and caches, `stream` and `alone` poll a stream into the cache, and `appsec` means **no
  decision source at all**.
- `appsecEnabled` toggles the **WAF leg**, which runs on the pass path in *every* mode
  (`bouncer.go:341`), not only in `appsec` mode.

So the ordinary combination is `stream` plus AppSec bouncerEnabled: decisions from the stream, and WAF on the
requests that survive them. And `appsec` mode is the only way to express "skip decisions, WAF only",
which is why it is the one mode that depends on the other knob being on.

Say explicitly that `lapiMode: appsec` with `appsecEnabled: false` enforces nothing, and
mention the warning from deliverable 2. Match the existing README style; do not restructure the table.

## Deliverable 4 — initialise the captcha client in appsec mode

`bouncer.New` returns early for appsec mode at `pkg/bouncer/bouncer.go:94`, before the captcha client
is initialised, so `captchaClient.Valid` stays false. When AppSec then fails with
`bouncerAppsecFailureAction: captcha`, `applyAppsecServeHTTP:353` raises `ErrFailureCaptcha`,
`handleRemediationServeHTTP:315` sees `!b.captchaClient.Valid`, and the request is **banned instead of
challenged**. Reproduced end to end through `plugin.New` with a config `ValidateParams` accepts: AppSec
returned 500, the operator had asked for captcha, and the client got `X-Remediation: ban` with a 403.

This is a violation of the project's own specification:
`openspec/specs/core_plugin_appsec_failure-action/spec.md` states that `captcha` SHALL use the
configured captcha client. Fixing it is roughly four lines: initialise the captcha client when appsec
mode needs it, and condition the early return accordingly.

Port only that. **Do not** bring across the rest of #33:

- Its error plumbing for `ip.NewChecker` (`bouncer.go:52-53`) and `GetTemplate` (`:65`) is unreachable
  defensive redundancy: `ValidateParams` already rejects the same inputs first
  (`configuration.go:319`, `:322`, `:362-366`), and `ip.Checker.ContainsIP` has an explicit nil guard
  commented "An uninitialized Checker trusts nothing" (`pkg/ip/checker.go:61-65`), so the swallowed
  error fails closed rather than panicking.
- Its 419-line `servehttp_test.go` uses a `testValidCaptchaClient(t, cacheClient)` helper that cannot
  compile: master's captcha client is stateless and takes no cache. `pkg/bouncer` already has around 28
  test functions over these paths.
- Its branch would nil-deref `lapiClient.Cache()` in appsec mode, where `lapiClient` is nil. Harmless
  on master because the argument is gone, but a reason not to copy from that branch.

One test proving that an AppSec failure with `bouncerAppsecFailureAction: captcha` serves the
challenge in appsec mode is the bar here.

## Deliverable 5 — snapshot Traefik's Config before mutating it

Salvaged from the closed #22. `New` writes through Traefik's pointer at `plugin.go:25`, `:29` and
`:32`, then hands the same pointer to `lapi.Prepare` (`pkg/lapi/client.go:80-96`, which writes the
resolved `LapiKey` and `LapiRedisPassword`, and in alone mode rewrites `LapiHost` and
forces `LapiUpdateIntervalSeconds = 7200`) and `appsec.Prepare` (`pkg/appsec/client.go:27-43`, writing
`AppsecKey`). Reproduced: after `New`, the caller's struct carries an upper-cased `LogLevel` and
the **resolved LAPI secret**.

No observable behaviour changes from fixing this — every mutation is idempotent and the reclaim
identity keys are computed after `Prepare` either way — which is why #22 was closed rather than merged.
It rides along here because it is three lines in a function you are already rewriting.

`prepared := *config` plus passing `&prepared` is the change. **But #22's version is a shallow copy**
while `Config` carries `[]string` and `map[string]string` fields the caller still shares. Either deep
copy those fields or leave a comment at the copy site saying they are shared, so the next person to add
an in-place slice mutation is not misled into thinking the snapshot protects them.

Because this is behaviour-neutral, it must not grow. If it starts requiring test changes beyond the
constructor, drop it and say so.

## How to prove it

Reproduce each defect first with a test that fails on `master` `87d1084`, then fix. The gates:

- `go build ./...`, `go vet ./...`, `go test ./pkg/... -count=1`
- `go test . -count=1` — **this one matters most here.** It is the Yaegi plus root e2e suite, and
  deliverable 1 turns on a `defer` with a named return. #31's own history shows commit `37e1914` broke
  the docker e2e on exactly that defer and `2535b19` fixed it, so the interpreter's handling of it is
  the known risk in this ticket.
- `golangci-lint run ./...` with `C:\Program Files\Git\usr\bin` prepended to `PATH`, so `goimports`
  can find `diff.exe`.
- `docker run --rm -v ${PWD}:/src -w /src -e CGO_ENABLED=1 golang:1.22.12 go test -race -count=1 ./pkg/...`
  — the host has no gcc, so Docker is the only way to run the race detector.

**You cannot run the real-stack Pester e2e locally.** It hard-codes host ports 8000, 8080 and 8081 plus
subnet `172.20.0.0/16`, and the owner's own long-running dev stack holds port 8000 and an overlapping
subnet. Do not stop his containers. Rely on the `e2e (docker + pester)` CI job on your pushed head, and
read the caveat below before believing a red result.

## Constraints

- Base off current `master` (`87d1084` at the time of writing; PR #74 may have advanced it, so fetch
  and use the real tip). Work in a worktree under `D:\repositories\wt-modsec-<branch>`.
- The main checkout holds the owner's uncommitted `AGENT-WORKLOG.md` and four untracked notes under
  `knowledge/debt/`. **Leave it alone.** In particular, never delete an untracked file from it: that
  already cost a debt note earlier today, and an untracked deletion cannot be reviewed or recovered.
- Do not merge, close, comment on or modify any pull request. The owner does that. Open your PR against
  `master` and stop.
- Yaegi v0.16.1 binds production code: no `atomic.Pointer[T]`, and avoid introducing new
  `select`-with-timer constructs, since `interp._select` loses timers.

## CI caveats, so you do not chase ghosts

A PR's checks run against the base it had when opened, so a green badge on an old PR proves nothing —
always look at `base.sha`. Two jobs are independently flaky right now: `e2e (docker + pester)` fails at
stack startup roughly at random (see `knowledge/debt/2026-09-18-e2e-pester-flaky-and-unrunnable-locally.md`),
and `pkg/lapi`'s race job has a known test-only race being fixed in PR #74. Before assuming a red check
is yours, compare the previous head's conclusions at
`api.github.com/repos/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/commits/<sha>/check-runs`.
Failure annotations are at `.../check-runs/<id>/annotations`. Both work without auth; raw Actions logs
do not, and the GitHub MCP has no tool for them.

## Not in this ticket

`#34` is next and separate: canonicalise both cache read sides using the `ipAddr net.IP` that
`LookupCachedRemediation` already receives, plus a guard so `ApplyRangeBatch` skips the write when
`readRangeIndex` cannot distinguish a miss from an error. Do not touch `pkg/decisionscope` keying here.
