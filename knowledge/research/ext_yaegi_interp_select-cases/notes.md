# Select case list sharing

yaegi v0.16.1 builds a `select` case list once per statement and reuses that slice in every goroutine that executes the statement. A `for range ch` receive builds a fresh `reflect.SelectCase` list on every execution and reads the channel from the current frame. Current yaegi master still does both of those things. This plugin still ships against Traefik’s bundled yaegi v0.16.1.

## v0.16.1 `_select` shares the case list

**Yes.** Tag `v0.16.1` is commit `3fbebb36621c03b2981ccee03246ea40455bd792`.

CFG assigns the generator once per `select` statement: `n.child[0].gen = _select`. `setExec` then calls `n.gen(n)` once, and later walks skip a node that already has `n.exec`.

Owner: `github.com/traefik/yaegi@3fbebb36621c03b2981ccee03246ea40455bd792:interp/cfg.go` (`selectStmt` around line 1911; `setExec` around line 2841). Extract: `.sources/cfg.go.md`.

`_select` allocates `cases := make([]reflect.SelectCase, nbClause+1)` in that generator, then closes over it in `n.exec`. Each run writes `cases[i].Chan` (and send values) from the current frame and calls `reflect.Select(cases)` on the **same** slice. Concurrent goroutines that execute that statement therefore race on `cases`.

```go
func _select(n *node) {
	nbClause := len(n.child)
	// ...
	cases := make([]reflect.SelectCase, nbClause+1)
	// ...
	n.exec = func(f *frame) bltn {
		f.mutex.RLock()
		cases[nbClause] = f.done
		f.mutex.RUnlock()

		for i := range cases[:nbClause] {
			switch cases[i].Dir {
			case reflect.SelectRecv:
				cases[i].Chan = chanValues[i](f)
			case reflect.SelectSend:
				cases[i].Chan = chanValues[i](f)
				cases[i].Send = assignedValues[i](f)
			// ...
			}
		}
		j, v, s := reflect.Select(cases)
		// ...
	}
}
```

Owner: `github.com/traefik/yaegi@3fbebb36621c03b2981ccee03246ea40455bd792:interp/run.go` (`_select`, lines 3749–3827). Extract: `.sources/run.go.md`. Permalink: https://github.com/traefik/yaegi/blob/3fbebb36621c03b2981ccee03246ea40455bd792/interp/run.go#L3749-L3827

`authority: inference` — the race across goroutines is not stated in a comment; it follows from one `cases` slice captured by one `n.exec` that mutates `Chan` in place.

## Range receive is evaluated per execution

**Yes.** A range over a channel uses generator `rangeChan` (`n.anc.gen = rangeChan` when `rangeChanType` is non-nil). Owner: `github.com/traefik/yaegi@3fbebb36621c03b2981ccee03246ea40455bd792:interp/cfg.go` (around lines 136–143). Extract: `.sources/cfg.go.md`.

`rangeChan` builds a **new** `[]reflect.SelectCase` inside `n.exec` and fills the receive case with `value(f)`, the channel from the current frame:

```go
func rangeChan(n *node) {
	i := n.child[0].findex        // element index location in frame
	value := genValue(n.child[1]) // chan
	// ...
	n.exec = func(f *frame) bltn {
		f.mutex.RLock()
		done := f.done
		f.mutex.RUnlock()

		chosen, v, ok := reflect.Select([]reflect.SelectCase{done, {Dir: reflect.SelectRecv, Chan: value(f)}})
		// ...
	}
}
```

Owner: `github.com/traefik/yaegi@3fbebb36621c03b2981ccee03246ea40455bd792:interp/run.go` (`rangeChan`, lines 2876–2897). Extract: `.sources/run.go.md`. Permalink: https://github.com/traefik/yaegi/blob/3fbebb36621c03b2981ccee03246ea40455bd792/interp/run.go#L2876-L2897

`authority: inference` — two goroutines ranging different ticker channels therefore do not share the receive `Chan`: each execution allocates its own case list and reads `value(f)` from that goroutine’s frame. Contrast `_select`, which mutates a generator-scoped slice.

## Current master still shares

**Still shared. Not fixed.** Shallow clone of `master` on 2026-09-26 is `fcb76d1ece0c3edc2548c39aa5b170475d2261bb` (`Fix nil pointer dereference when sending to binary channel type alias`). `_select` and `rangeChan` in `interp/run.go` are **byte-identical** to v0.16.1. Master CFG still sets `n.child[0].gen = _select` and still calls `n.gen(n)` once from `setExec`.

Owners: `github.com/traefik/yaegi@fcb76d1ece0c3edc2548c39aa5b170475d2261bb:interp/run.go`; `github.com/traefik/yaegi@fcb76d1ece0c3edc2548c39aa5b170475d2261bb:interp/cfg.go`. Extracts: `.sources/run.go-master.md`, `.sources/cfg.go-master.md`.

This shallow master clone has no tag history, so this run cannot name a post-v0.16.1 commit that changed `_select`. The identical function bodies are the evidence there was no such change on the inspected tip.

This plugin still ships against Traefik’s bundled v0.16.1: Main CI sets `YAEGI_VERSION: v0.16.1` and states Traefik v3.7.1 ships that interpreter; `pkg/yaegitest` runs the v0.16.1 binary the way Traefik loads the module. Owners: `this-repo@deb8ebfe0f2aefa19b62102fd85878b4882dc42f:.github/workflows/main.yml`, `pkg/yaegitest/interpreter.go`. Extracts: `.sources/main.yml.md`, `.sources/interpreter.go.md`. This run did not re-read Traefik’s `go.mod`.

## Issue 377 (stream vs metrics stall)

Reporter: in `stream` mode the plugin stops calling `GET /v1/decisions/stream` for about 20 minutes, then resumes; `POST /v1/usage-metrics` keeps firing on its own cycle. Traefik kept serving. Environment named plugin v1.7.1 and Traefik v3.7.10. Resume logged two `handleStreamCache:updated` lines 1 ms apart.

Owner: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/377 (`authority: ticket`). Extract: `.sources/issue-377.md`.

A later collaborator comment (2026-09-25) attributes that gap to yaegi `_select` sharing and points at PR 399. That comment is not the owner of interpreter behavior (`authority: comment`). Extract: `.sources/issue-377-comment-cause.md`.

## PR 399 (range-over-ticker)

PR body (`authority: comment`): both ticker loops ran the same `select` in `startTicker`; under yaegi they could wait on each other’s ticker channel. Stream-on-metrics-channel produces a gap of one or two metrics intervals (the 1200 s in #377). The PR ranges over the ticker channel instead, drops the unused `stop` channel, and returns `*time.Ticker`.

Patch files (`authority: source`): `startTicker` becomes `go runTicker(ticker.C, work)` and returns the ticker. `runTicker` is `for range ticks { go work() }`. Package globals `streamTicker` / `metricsTicker` change from `chan bool` to `*time.Ticker`. Test `Test_runTicker_keepsEachTickerOnItsOwnChannel` starts two `runTicker` loops on two channels, sends 20_000 ticks on each, and fails if either work func did not run exactly 20_000 times (the idea: each loop must stay on its own channel).

Owners: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/399 (prose); `maxlerebourg/crowdsec-bouncer-traefik-plugin@dca428958ae6c50e3750fbc9303be9a87a2c0553:bouncer.go`, `ticker_test.go` (patch). Extracts: `.sources/pull-399.md`, `.sources/bouncer.go.md`, `.sources/ticker_test.go.md`.
