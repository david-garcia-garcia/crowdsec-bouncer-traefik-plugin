# Ticket source: single-flight the stream poll

Scratch source for the ticket. Copy to `ticket/source.md` in the bus folder and delete this file
from the repository root.

Supersedes open PRs **#30** and **#42**. Both target this area; neither is mergeable as-is. Close
them when this lands, with a comment pointing here. Do not close them before, and only with the
owner's approval.

Scope fence: `pkg/lapi` plus its `zzz_` tests, and `.github/workflows/main.yml` for the race gate
described below. Do not touch `pkg/bouncer`, `pkg/cache`, `pkg/configuration`, captcha, appsec or
reclaim. Do not change the lease design.

Three deliverables, all in this one PR, each called out separately in the PR body so a reviewer can
tell them apart:

1. The single-flight fix and the atomic flags (the actual bug).
2. The test-harness race fix in `TestSleepDrainsMetrics`, which is test-only and must not be
   presented as part of the production bug.
3. A CI job that actually runs the race detector, since none exists today.

## Problem, proven on master `b42860f8`

`startTicker` spawns a goroutine per tick and never waits for the previous one:

```247:263:pkg/lapi/client.go
func startTicker(name string, updateInterval int64, log *slog.Logger, work func()) chan bool {
	ticker := time.NewTicker(time.Duration(updateInterval) * time.Second)
	stop := make(chan bool, 1)
	go func() {
		defer log.Debug(name + "_ticker:stopped")
		for {
			select {
			case <-ticker.C:
				go work()
```

Three `Client` fields are written by that work and read from the request path with no
synchronization at all: `isCrowdsecStreamStartup`, `isCrowdsecStreamHealthy`, `updateFailure`.
`Client` has a `mu sync.Mutex`, but it guards lifecycle state (`closed`, `sleeping`, ticker stop
channels) and the live header-scope registry, and it is not held around these three.
`StreamHealthy()` (`client.go:306-308`) is a raw read, and `pkg/bouncer` calls it on every
stream/alone cache miss (`bouncer.go:208-216`). `streamQuery` (`client_decisions.go:16`) also reads
two of them unlocked.

Verified with the race detector in a `golang:1.22.12` container (`CGO_ENABLED=1 -mod=vendor`),
driving a 1s ticker against a 2.2s LAPI. Two poller goroutines racing each other, both spawned by
the ticker:

```
WARNING: DATA RACE
Read at 0x00c000282129 by goroutine 32:
  (*Client).handleStreamTicker()  pkg/lapi/client_stream.go:59
Previous write at 0x00c000282129 by goroutine 25:
  (*Client).handleStreamTicker()  pkg/lapi/client_stream.go:62
Goroutine 32 created at: startTicker.func1()  pkg/lapi/client.go:255
Goroutine 25 created at: startTicker.func1()  pkg/lapi/client.go:255
```

Same run reached three concurrent in-flight LAPI calls and four fetches in 3.5 seconds. A separate
race was captured between the poller writing `isCrowdsecStreamHealthy` and the request path
reading it through `StreamHealthy()` (`client.go:307`).

**The cache lease does not fix this.** `handleStreamCache` takes a lease with TTL
`max(updateInterval-1, 1)` (`client_stream.go:67-82`). It is an inter-instance and inter-process
fetch lock, not an intra-instance poll lock. Two things follow. It can expire before a slow poll
finishes, so at the default interval 60 a poll longer than ~59s simply wins again. And even when
the lease correctly blocks the second fetch, the losing goroutine still writes
`isCrowdsecStreamStartup` on its early-return path, so the data race remains. That was reproduced
separately with `updateInterval=60` and a short poll.

**A pre-existing test already trips it.** `TestOpenStream_SleepingIntervalChangeWakesSameSlot`
races `Wake`'s `go handleStreamTicker()` write of `isCrowdsecStreamStartup`
(`client_stream.go:80`) against an unsynchronized read. This is not hypothetical.

## Consequences, worst first

Two simultaneous winners after a lease expiry interleave cache `Set`/`Delete` and the
read-modify-write of the range blob (`pkg/decisionscope/range.go:23-44`), which can drop a CIDR and
therefore produce a wrong allow or ban. That needs a slow or large apply, so it is rare.

More likely to be observed: overlapping success and failure writes flap
`isCrowdsecStreamHealthy`, and with the default `LapiUpdateMaxFailure=0` the first failure already
marks the stream unhealthy. Cache-miss requests then get `BouncerLapiFailureAction`, which
defaults to `ban`. Cached hits are unaffected.

Also: duplicate `GET /v1/decisions/stream` load, and `startup=true` versus `startup=false`
disagreement between overlapping `streamQuery` reads causing an extra full snapshot.

Reachable at stock settings: `Sleep` and `Close` only signal the stop channel
(`client.go:167-170`, `193-196`) and do not wait for in-flight work, while reclaim grace is 30s and
the default HTTP timeout is 10s. So a Traefik reload can `Wake` and start a fresh poll while the
previous one is still running, with no unusual configuration at all.

## Decided fix

1. **Skip the tick if a poll is already running.** Guard `handleStreamTicker` with a dedicated
   in-flight flag, released on all paths including panic. This must also cover the two non-ticker
   spawn sites: `startStream`'s async first poll when `LapiStreamStartupBlock` is false
   (`client_stream.go:41`) and `Wake` (`client.go:225`). Dropping a tick is the correct stream
   semantic; do not queue polls.
2. **Publish the three flags atomically, regardless of item 1.** Item 1 removes poller-versus-poller
   overlap but not poller-versus-request-path, since `ServeHTTP` reads `StreamHealthy()` while a
   poll writes it. Do **not** take `Client.mu` across the HTTP call: that mutex is lifecycle plus
   the scope-union registry, and holding it would stall `Sleep`, `Close` and
   `registerLiveHeaderScopes`.
3. **Remove `go` from `startTicker`** (`client.go:255`) so `work()` runs on the ticker goroutine
   instead of spawning a skipper every tick. `stop` is buffered, so `Sleep` still returns
   immediately. This is decided, not optional, but it is not sufficient on its own because `Wake`
   spawns directly.

### Yaegi constraint on how to make the flags atomic

Decided: **int64 fields with `atomic.LoadInt64` / `atomic.StoreInt64`**, mirroring the existing
`streamFetches` field in the same struct.

Do not use `atomic.Pointer[T]` as a struct field; already forbidden by
`knowledge/devdocs/core_plugin_lapi_connection.md`. Do not use `atomic.Bool` or `atomic.Int64`:
nothing in this repo uses them yet, so their behaviour under Yaegi v0.16.1 is unproven, and the
owner chose not to spend a probe on it. `transport`, `rangeMembership` and `lastRangeIndex` use
`atomic.Value` if you need a precedent for a non-scalar.

### Rejected approaches, do not revisit

A mutex that queues ticks while `go work()` remains: waiters grow without bound whenever the poll
outlasts the interval.

A new `for { timer; work() }` loop or a second `select` on `ticker.C`: Yaegi v0.16.1 `interp._select`
can lose a timer wake, which is exactly why reclaim uses `time.AfterFunc`
(`knowledge/devdocs/std_go_reclaim.md`). The existing `startTicker` select already exists and works;
do not add another copy and do not try to "fix" it with a second select loop.

Relying on the lease: covered above.

## Test plan

Convention is the `zzz_` filename prefix. Add to `pkg/lapi/zzz_client_stream_test.go` or a sibling
`pkg/lapi/zzz_client_stream_overlap_test.go`, reusing `testStreamLAPI`, `attachTestTransport` and
`newSharedStreamPoller`.

**Deliverable 2, clear this first:** `pkg/lapi` is not race-clean today, so "assert the detector is
silent" is unusable until it is. `TestSleepDrainsMetrics` in `zzz_metrics_test.go` races a test
reader against the mock metrics handler. That is test-harness only, not production. Fix the harness
so the package can be race-clean, and label it plainly in the PR as a test fix so nobody mistakes it
for part of the production bug.

Cases that must fail on today's master and pass after:

1. Slow poll longer than the interval: 1s ticker, LAPI sleep above 1s, `LapiStreamStartupBlock=false`.
   Assert at most one in-flight poll, that fetches do not climb one per tick, and that the detector
   is silent.
2. Two overlapping polls with the lease still valid (interval 60, short poll). One fetch, and the
   losing goroutine does not race the flag writes.
3. Request-path `StreamHealthy()` read concurrent with a poll write.
4. `Sleep` then `Wake` while a poll is in flight: at most one GET, no second `startup` write race.

Keep the existing lease tests passing unchanged: `TestHandleStreamCacheIntervalOneStoresLease`,
`TestHandleStreamCache_TwoMemoryPollersOneFetch` and the Redis twin must still show one winner.

## How to run the race gate locally

`go test -race` does not work on the owner's Windows host: no C compiler, so cgo is unavailable, and
the owner declined to install one. Use Docker, which is how the investigation was done:

```
docker run --rm -v ${PWD}:/src -w /src -e CGO_ENABLED=1 golang:1.22.12 go test -race -count=1 -mod=vendor ./pkg/lapi/
```

A case that only passes without `-race` is not done. Report the container output in the PR.

## Deliverable 3: a CI race job

Today nothing detects races. `.github/workflows/main.yml:26` sets `CGO_ENABLED: 0` for the whole
`main` job and no workflow passes `-race`. The owner decided this needs a real CI job rather than
relying on someone remembering to run Docker.

Add a **second job** to `.github/workflows/main.yml`, not a step inside `main`, so the job-level
`CGO_ENABLED: 0` does not have to be fought. Mirror the existing job's setup: `ubuntu-latest`,
`GO_VERSION: 1.22` (capped because Traefik ships Yaegi v0.16.1, which only supports Go 1.22 — do not
raise it), `actions/setup-go@v7`, `actions/checkout@v7` into the same
`go/src/github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin` path with the same
`defaults.run.working-directory`, the module cache, and `go env -w GOPATH`. Set `CGO_ENABLED: 1` for
this job. It does not need golangci-lint or Yaegi.

Run `go test -race -count=1 ./pkg/...`.

If packages other than `pkg/lapi` turn out to have races, do not silently narrow the job to hide
them. Either fix them if they are trivial test-harness issues of the same kind, or list them in the
PR and scope the job to the packages that pass plus `pkg/lapi`, stating exactly which packages were
excluded and why. The owner needs to see that list.

Do not add `-race` to the root-package suite (`go test -race .`): it sleeps through reclaim grace and
already takes about 50 seconds without the detector.

While you are in that file, note but do NOT fix: the workflow triggers on `push` to `main`, yet this
repository's default branch is `master`, so pushes to master never run CI and only pull requests do.
Mention it in the PR as an observation for the owner. It is out of scope here.

## Gates before proposing for merge

Merge current `origin/master` into the branch first. Then `go build ./...`, `go vet ./...`,
`go test ./pkg/... -count=1`, `go test . -count=1` (the ~50s root suite, mandatory), and
`golangci-lint run ./...` with `C:\Program Files\Git\usr\bin` prepended to PATH. Master lints clean
as of `b42860f8`, so any finding is yours. Plus the Docker race run above.

Do not merge. The owner approves every merge personally.
