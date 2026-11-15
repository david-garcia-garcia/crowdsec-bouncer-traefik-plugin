# Keep each LAPI Client's ticker loops isolated under yaegi

Upstream review 2026-11-14, problem 9 ("Posible parada silenciosa del stream con varios middlewares").

yaegi v0.16.1 builds one `[]reflect.SelectCase` per `select` statement and every goroutine that runs that statement mutates the same slice (`knowledge/research/ext_yaegi_interp_select-cases/`). Fork commit 886d88bd (#171) split the stream and metrics loops into `runStreamTicker` / `runMetricsTicker` so the two loops of ONE Client no longer share a statement.

That split does not cover several Clients. `lapi.Open` reclaims one `lapi.Client` per ownership key, and `OwnershipKey` includes the middleware name (`pkg/lapi/identity.go`). Every Client starts its own `runStreamTicker` (stream/alone) and `runMetricsTicker` goroutine. With two or more LAPI middlewares, during a reload that changes a client knob (old Client in reclaim grace beside the new one), or across Sleep→Wake, several goroutines execute the same `select` statement.

Reproduced on this machine under yaegi v0.16.1: two goroutines in `lapi.RunStreamTickerForTest`, each on its own tick channel, 200 000 sends per channel, `GOMAXPROCS(2)`. 5 of 5 runs failed, with 2–12 ticks received by the wrong loop (`a=200011 b=199989 want=200000`).

Consequences:
- Fact: a tick from one Client's ticker runs another Client's poll. One poll is skipped or doubled; it self-heals.
- Inference from the mechanism (not reproduced): if Client B is Slept/Closed while Client A waits on B's channels, either A consumes B's stop and A's stream stops forever with `StreamHealthy` still true while closed B keeps polling, or B exits and A blocks forever on B's stopped ticker. Either way a middleware's stream silently stops updating decisions. The metrics loop has the same exposure across Clients.

Desired:
- Each Client's stream loop and metrics loop receives only its own ticks and its own stop, under yaegi v0.16.1, no matter how many Clients run the same loop code.
- Stopping one Client (Sleep or Close) never stops or stalls another Client's loops, and the stopped Client's loop actually ends.
- Sleep, Wake, and Close keep their current contract: Sleep/Close signal the loops and do not wait for or cancel an in-flight stream GET; Wake restarts them.
- Proposed direction from the review: replace the `select` with rescheduling via `time.AfterFunc` (pattern already used by reclaim to avoid the yaegi `_select` share). Explore decides.
- Regression tests: a yaegi test with several loops of the SAME kind on their own channels that fails on master, and a test that stopping one loop leaves another running. Native `go test` isolation is not proof of the yaegi bug.
- Run tests on this machine.

Out of scope: other upstream review problems; workflow files; changing LAPI poll semantics beyond what the loop fix needs.

Upstream (must appear on the delivery card):
- PR https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/399 — upstream's fix for the shared select (range over `ticker.C`, drop stop). Not copied: `Ticker.Stop` does not close `C`, so a ranging goroutine never exits after Sleep/Close.
- Issue https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/377 — stream stopped polling for up to ~20 minutes under yaegi with no error.
