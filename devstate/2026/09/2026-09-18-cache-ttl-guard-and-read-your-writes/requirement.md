# Requirement

Rebuilt from open PR #38 (`fix(cache): align Redis TTL, errors, and read-your-writes`), trimmed by
triage to two deliverables. #38 stays OPEN as the requirement source; the owner closes it.

## Deliverable 1 — a non-positive TTL is a no-op

`pkg/cache` has no guard for `duration <= 0`, so the value reaches the backend. The two backends
disagree, and the in-memory one produces exactly the dangerous outcome: an entry that never expires,
so a cached ban outlives the decision that justified it.

Make a non-positive duration a no-op on every write path, with a failing-first test per backend.

## Deliverable 2 — read your own writes where a stale read changes the decision

Every cache read goes through `redisCache.nextReader()` round-robin. With `RedisCacheReadHosts`
pointed at a lagging replica, a just-banned IP reads back as a miss, and stream/alone mode treats a
miss as "no decision affecting this IP" (`bouncer.go:212-222`), so the plugin serves the request it
had already decided to block.

Fix only the read paths where a stale value changes the remediation actually served. Do **not**
convert the whole cache to writer-only reads: the read replicas carry per-request lookup load and
removing that is a regression every request pays.

Constraints:

- No new configuration knob without stopping to ask.
- The stream lease is already correct (`Acquire` runs against the writer). Do not redesign it.
- Name the mechanism and argue it against the alternatives. The argument is the deliverable.

## Explicitly out of scope

Propagating `error` through the cache API (#38's third part). Triage dropped it: the plumbing touches
every call site and the caller can only log, which already happens. A call site where a swallowed
cache error genuinely changes behaviour is a `knowledge/debt/` note, not a widening of this PR.

## Fences

- Scope is `pkg/cache` semantics. **Do not touch cache key construction** — PR #77
  (`2026-09-18-ip-cache-key-canonicalization`) is changing how IP keys are spelled.
- Redis plumbing lives upstream in `simpleredis` (`traefik-middleware-utilities` v1.0.3). A defect
  inside that package is a stop-and-report, not a vendor patch or a fork.
- Dedicated worktree. Never modify or delete anything in the main checkout beyond the one root
  scratch ticket file.
- Base on `origin/master`, target `master`. `main` is stale and must never be used.
- Do not merge, close, or comment on any PR, #38 included.

## Proof bar

- Failing-first test per deliverable, surviving into the PR.
- Deliverable 2: a stale-read decision flip demonstrated before the fix and absent after, against a
  deliberately lagging or distinct read host.
- `go build ./...`, `go vet ./...`, `go test ./pkg/... -count=1`, `go test . -count=1` (yaegi, ~50s),
  `golangci-lint run ./...` (needs `C:\Program Files\Git\usr\bin` on `PATH` for `diff.exe`).
- `-race` via Docker: `docker run --rm -v ${PWD}:/src -w /src -e CGO_ENABLED=1 golang:1.22.12 go test -race -count=1 ./pkg/...`
- CI read with plain `curl` on `/commits/<sha>/check-runs`; the MCP combined-status call reports
  `pending` with `total_count: 0` forever because these are Actions check-runs.
