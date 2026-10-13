# Ticket source: canonicalize IP cache keys, and guard the range-index apply

Scratch source for the ticket. Copy to `ticket/source.md` in the bus folder and delete this file
from the repository root.

Suggested key: `2026-09-18-ip-cache-key-canonicalization`.

Rebuilt from open PR **#34** (`fix(ip): align Ip cache keys and guard range-index apply`), which the
owner has decided to close in this ticket's favour once this lands. Do not merge #34 and do not reuse
its branch. Read its diff for intent only, then reimplement against current `master`. The owner
decided both halves belong in the same ticket.

Everything below was established by a triage pass plus one empirical experiment. Treat each claim as
a hypothesis to re-verify, and correct this ticket in the bus folder if reality differs.

## Deliverable 1 — key the IP cache on a canonical spelling, on both sides at once

**The defect.** The plugin can write a cache entry for an address under one textual spelling and then
look it up under a different spelling of the same address, so the entry is never found. Decision
values arriving from LAPI are used verbatim as the write-side key; the read side keys on the string
form taken from the request's remote address / forwarded header.

**What was measured, and why it matters.** A throwaway CrowdSec container was used to settle how
CrowdSec itself treats IPv6 spellings. Result: CrowdSec **stores the textual value verbatim** as it
was submitted, but **matches numerically** when LAPI is queried. So LAPI lookups are not the problem
and need no workaround — the asymmetry is entirely inside the plugin's own cache keying, which
compares strings. That makes the fix nearly free, because a canonical `net.IP` is already parsed and
in hand on the read path: `ip.GetRemoteIP` returns both the raw string and the `net.IP`.

**The trap, and the reason this deliverable is phrased as "both sides at once".** #34's original patch
canonicalized only the read sides. That was measured to *regress* live-mode caching: a value written
under its verbatim spelling and then read under the canonical spelling becomes a permanent miss,
which is worse than the bug being fixed. Any patch that changes one side must change the other in the
same commit. Your proof must include a measurement showing live-mode caching still hits after the
change — not merely that tests pass.

**Shape of the fix.** Normalize through the parsed address on both sides: the already-parsed `net.IP`
on the read path, and a parse-then-`String()` of the decision value on the write path, falling back to
the verbatim value when it does not parse as an IP. Confirm for yourself where those sites are; the
read path runs through `LookupCachedRemediation` in `pkg/lapi`, which already accepts both `remoteIP`
and `ipAddr`.

**Must not change.** No new configuration knob. Non-IP scopes are untouched — country and AS values
are not addresses and must not be pushed through IP parsing. Range decisions keep being served by the
range index rather than by exact-key lookups.

## Deliverable 2 — guard the range-index apply

#34's second half guards the range-index apply path. Read the PR's diff for the exact defect and
prove it with a test that fails before your change and passes after. If, once you have the evidence
in front of you, the guard turns out to be unreachable or purely cosmetic, say so in the review and
drop it rather than shipping a change with no observable effect — that is a legitimate outcome, and
it is what happened to a sibling PR in this queue.

## Proof bar

- A failing-first test for each half that survives into the PR.
- The live-mode caching measurement described above, with the numbers in the review.
- Full local gates: `go build ./...`, `go vet ./...`, `go test ./pkg/... -count=1`, `go test . -count=1`
  (the yaegi suite, ~50s), and `golangci-lint run ./...`. The linter needs
  `C:\Program Files\Git\usr\bin` prepended to `PATH` so `goimports` can find `diff.exe`.
- `-race` is unavailable on the host (no C compiler). Run it in Docker:
  `docker run --rm -v ${PWD}:/src -w /src -e CGO_ENABLED=1 golang:1.22.12 go test -race -count=1 ./pkg/...`

## Process constraints

- Work in a dedicated worktree, `D:\repositories\wt-modsec-<branch>`. Do not touch the main checkout
  at `D:\repositories\crowdsec-bouncer-traefik-plugin`, which holds the owner's uncommitted and
  untracked work. In particular, never delete untracked files there.
- Base on current `origin/master` and open the PR against `master`. `main` is a stale branch 40+
  commits behind and must not be used.
- **Do not merge, close, or comment on any pull request.** The owner merges. Leave your PR open and
  report its number.
- Push and confirm all CI checks pass, including `Race detector` and `e2e (docker + pester)`. The
  latter is known to flake with "no test-results.xml"; a single re-run is the accepted remedy.

## What to report back

The PR number and head sha; the two defects as you finally understood them, with the failing-first
evidence for each; the live-mode caching numbers before and after; the race run count; gate and CI
results; and anything you deliberately did not do, with the argument.
