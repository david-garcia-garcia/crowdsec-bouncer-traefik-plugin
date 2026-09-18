# Ticket source: guard non-positive cache TTLs, and read your own writes where it changes a decision

Scratch source for the ticket. Copy to `ticket/source.md` in the bus folder and delete this file
from the repository root.

Suggested key: `2026-09-18-cache-ttl-guard-and-read-your-writes`.

Rebuilt from open PR **#38** (`fix(cache): align Redis TTL, errors, and read-your-writes`). Do not
merge #38 and do not reuse its branch: the spec file it edits was deleted from `master`, and its diff
predates the `context.Context` threading that #66 introduced. #38 stays open as a requirement source
until this lands; the owner will close it, not you.

A triage pass already verified all three of #38's claims are still alive on `master` and then
**deliberately trimmed the third away**. Take the trim as decided, not as an open question. Re-verify
the evidence for yourself, and correct this ticket in the bus folder if reality differs.

## Deliverable 1 — treat a non-positive TTL as a no-op

`set` and `delete` (`pkg/cache/cache.go:149,155`) and `Client.Set` / `Client.Delete`
(`pkg/cache/cache.go:214,234`) have no guard for `duration <= 0`. Establish what each backend does
today with a zero or negative TTL — in-memory and Redis are not obliged to agree, and "writes an entry
that never expires" is the dangerous outcome to look for, because a decision cached forever outlives
the ban that justified it. Then make a non-positive duration a no-op, and prove the before/after with
a test per backend.

## Deliverable 2 — read your own writes, but only where a stale read changes the decision

Every read goes through `nextReader()` round-robin. With `RedisCacheReadHosts` pointed at a lagging
replica, an IP that was just banned can be read back as not banned: the plugin lets through the
request it had already decided to block. That is the defect, and it is a security-relevant one.

Scope this narrowly. Enumerate the read paths where a stale value changes the remediation actually
served, and fix those. Do not convert the whole cache to writer-only reads: read replicas exist to
carry the per-request lookup load, and taking that away is a performance regression paid by every
request to fix a window that only some deployments have.

Constraints on the design:
- **No new configuration knob without asking.** This repository has twice now rejected a PR whose knob
  turned out to be reachable with existing configuration. If you conclude a knob is genuinely
  necessary, stop and report rather than adding one.
- The stream lease is already correct: `Acquire` runs against the writer. Do not redesign it.
- Say plainly which mechanism you chose (for example, pinning reads for a key to the writer for a
  bounded window after writing it) and why the alternatives are worse. The mechanism is your call; the
  argument for it is the deliverable.

## Explicitly NOT in scope: propagating `error` through the cache API

This was #38's third part and the triage dropped it. The reasoning, which you should not relitigate
without new evidence: threading `error` return values through every cache call site is expensive
plumbing, and the callers cannot do anything with the error beyond logging it, which already happens.
If, while working, you find a call site where a swallowed cache error genuinely changes behaviour,
record it as a debt note with the file and line — do not widen this PR.

## Fences

- Your scope is `pkg/cache` semantics. **Do not touch cache key construction.** A parallel ticket
  (`2026-09-18-ip-cache-key-canonicalization`, PR #77) is changing how IP keys are spelled, in
  `pkg/lapi` and the decision-scope paths. If you believe a key must change, stop and report.
- Redis plumbing itself lives upstream in `simpleredis`, from `traefik-middleware-utilities` (v1.0.3,
  read-only clone at `D:/repositories/traefik-middleware-utilities`), which `pkg/cache` imports. If the
  defect you need to fix is inside that shared package, **stop and report it — do not vendor or fork
  it.** The house rule is that such fixes go to the utilities repository.

## Proof bar

- A failing-first test for each deliverable that survives into the PR.
- For deliverable 2, a demonstration with a deliberately lagging or distinct read host showing the
  stale-read decision flip before the fix and its absence after.
- Full local gates: `go build ./...`, `go vet ./...`, `go test ./pkg/... -count=1`, `go test . -count=1`
  (the yaegi suite, ~50s), and `golangci-lint run ./...`. The linter needs
  `C:\Program Files\Git\usr\bin` prepended to `PATH` so `goimports` can find `diff.exe`.
- `-race` cannot run on the host (no C compiler). Use Docker:
  `docker run --rm -v ${PWD}:/src -w /src -e CGO_ENABLED=1 golang:1.22.12 go test -race -count=1 ./pkg/...`

## Process constraints

- Work in a dedicated worktree, `D:\repositories\wt-modsec-<branch>`. Do not touch the main checkout
  at `D:\repositories\crowdsec-bouncer-traefik-plugin`; it holds the owner's uncommitted and untracked
  work, and **never delete an untracked file there** — doing so destroyed a debt note earlier today.
- Base on current `origin/master` and open the PR against `master`. `main` is stale and must not be used.
- **Do not merge, close, or comment on any pull request**, #38 included. The owner merges and closes.
- Push and confirm CI. Note that the MCP's combined-status call reports `pending` with `total_count: 0`
  forever, because these are Actions check-runs: read
  `https://api.github.com/repos/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/commits/<sha>/check-runs`
  instead, which needs no auth. `e2e (docker + pester)` is known to flake with "no test-results.xml";
  one re-run is the accepted remedy.

## What to report back

The PR number and head sha; what each backend actually did with a non-positive TTL before your change;
the enumerated read paths and which you fixed, with the mechanism and the argument for it; the
stale-read demonstration; gate and CI results; and anything you deliberately did not do, with reasoning.
