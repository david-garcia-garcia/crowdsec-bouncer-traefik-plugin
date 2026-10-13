# Ticket source: fail closed on header-scope LAPI errors, and harden `crowdsecQuery`

Scratch source for the ticket. Copy to `ticket/source.md` in the bus folder and delete this file
from the repository root.

Suggested key: `2026-09-18-lapi-scope-failclosed-query-hardening`.

Extracted from open PR **#30** (`fix(lapi): serialize stream polls, harden HTTP query, propagate
scope errors`), which the owner decided to close in favour of this rebuilt ticket. Do not merge #30
and do not reuse its branch. Its serialization half is already on master via #72 and its remaining
half predates #62's `transport` rework, so it cannot be rebased cleanly. Take the *intent* of the
hunks listed below and reimplement them against current master. #42 is already closed as superseded.

Closing #30 is the owner's action, not yours. Do not close it.

Scope fence: `pkg/lapi` plus its `zzz_` tests, and `README.md` only for the operator-visible
behavior change in deliverable 1. Do not touch `pkg/cache`, `pkg/captcha`, `pkg/appsec`,
`pkg/reclaim`, `pkg/ip`, the reclaim design or the stream lease *design* (deliverable 2 fixes a
missing release, it does not redesign leasing). Touch `pkg/bouncer` only if deliverable 1 genuinely
cannot be done in `pkg/lapi` alone; if you do, justify it in the PR body.

Do not touch the three existing debt notes in `knowledge/debt/` (`2026-09-18-logger-file-reclaim.md`,
`2026-09-18-trace-header-untrusted-value.md`, `2026-09-18-release-pipeline-targets-stale-main.md`).
They are waiting on a separate docs PR.

Base on current master `0e7dbf0`. Five deliverables, each called out separately in the PR body so a
reviewer can tell them apart. Deliverable 1 is a security fix and a behavior change; 2 and 3 are
correctness; 4 and 5 are hygiene found while reviewing #30 and #42, folded in here by owner decision
because they live in the same function as 3.

## Deliverable 1 (SECURITY, behavior change): header-scope LAPI errors must not silently allow

`mergeLiveScope` cannot report failure. Its signature returns only `(string, time.Duration)`:

```130:138:pkg/lapi/client_decisions.go
func (c *Client) mergeLiveScope(chosen string, parsedDuration time.Duration, scope, identifier string, isLiveMode bool, defaultDecisionSeconds int64) (string, time.Duration) {
	if identifier == "" {
		return chosen, parsedDuration
	}
	headerChosen, headerDuration, headerErr := c.queryLiveDecisions("scope=" + url.QueryEscape(scope) + "&value=" + url.QueryEscape(identifier))
	if headerErr != nil {
		c.log.Debug("handleNoStreamCache:scopeQuery " + scope + " " + headerErr.Error())
		return chosen, parsedDuration
	}
```

A failed scope query is therefore indistinguishable from "this scope has no decision", and the
caller loses the error entirely:

```23:25:pkg/lapi/client_live.go
	for scope, identifier := range scopes {
		chosen, parsedDuration = c.mergeLiveScope(chosen, parsedDuration, scope, identifier, isLiveMode, defaultDecisionSeconds)
	}
```

Consequence: in `none` and `live` mode, a LAPI that answers the IP query but errors on a header-scope
query produces `NoBannedValue, nil`, so `pkg/bouncer` takes the allow path and
`crowdsecLapiFailureAction` never applies. It is logged at `Debug`, which is off in most deployments,
so the allow is silent. The IP query's error does propagate
(`pkg/lapi/client_live.go:19-21`), so a fully-down LAPI is still handled; the hole is a live LAPI
failing only the scope call. For a security control this fails the wrong way.

Fix so that a scope-query failure reaches the caller and is treated exactly like an IP-query failure,
letting the operator's configured `crowdsecLapiFailureAction` decide.

**Beware the overloaded error.** `handleNoStreamCache` already uses a non-nil error to signal a ban:

```32:36:pkg/lapi/client_live.go
	if isLiveMode && defaultDecisionSeconds > 0 {
		c.cacheClient.Set(remoteIP, chosen, liveCacheTTL(parsedDuration, defaultDecisionSeconds))
	}
	return chosen, errors.New("handleNoStreamCache:banned")
```

`pkg/bouncer` disambiguates by checking `decisionscope.IsActiveRemediation` on the returned kind
before consulting the failure action (`pkg/bouncer/bouncer.go:233-245`). So a failure error must come
back with a **non-active** remediation, and a ban must keep coming back as active. Do not collapse
the two. If that distinction is too subtle to leave implicit, make it explicit in the code rather
than clever.

Required behavior matrix, one test per row, all rows must be asserted:

| IP query | scope query(s) | expected result |
|---|---|---|
| clean | all succeed, no decision | allow, no error |
| clean | one errors | error surfaced with non-active kind, so `crowdsecLapiFailureAction` applies |
| clean | one returns ban | ban wins |
| active ban | one errors | **ban wins**, the error must not downgrade or mask it |
| errors | not reached / any | existing behavior unchanged, IP error propagates |
| clean | two scopes, one errors and one returns ban | ban wins |

Raise the swallowed `Debug` log to a level an operator will actually see, consistent with how other
LAPI failures are logged in this package. Check what the package already uses before picking.

This is operator-visible: a deployment with a flaky scope path that silently allowed will now apply
the failure action, whose default is **ban**. Document it in `README.md` next to
`crowdsecLapiFailureAction`, state plainly that scope-query failures now honour it, and say which
value restores permissive behavior. Verify the accepted values in
`pkg/configuration` rather than guessing, and mention it prominently in the PR body under a heading
the owner cannot miss.

## Deliverable 2: release the stream lease when the stream GET fails

`handleStreamCache` wins the lease, then returns on a failed GET without releasing it:

```80:100:pkg/lapi/client_stream.go
	won, err := c.Cache().Acquire(context.Background(), cacheTimeoutKey, decisionscope.NoBannedValue, leaseDuration)
	...
	body, err := c.crowdsecQuery(streamRouteURL.String(), nil)
	if err != nil {
		return err
	}
```

Lease TTL is `max(updateInterval-1, 1)`. So after a failed poll nothing retries until it expires,
neither this instance nor any other. With the default `UpdateMaxFailure=0` the stream is already
marked unhealthy on the first failure, so this stretches the window in which stream/alone cache
misses take `CrowdsecLapiFailureAction`, default **ban**.

Release the lease on every failure path that got past a won `Acquire`, so the next tick can retry
immediately. Deleting `cacheTimeoutKey` is how #30 did it; confirm that matches the cache API on
current master and that it is correct for both the Redis and in-memory implementations. Do not
change the lease TTL or the acquire semantics. Consider whether a later failure in the same function
(JSON unmarshal, apply) should release too, and say what you decided and why.

## Deliverable 3: the alone-mode 401 retry drops the request body

```218:222:pkg/lapi/client_http.go
	if res.StatusCode == http.StatusUnauthorized && c.crowdsecMode == configuration.AloneMode {
		if errToken := c.getToken(); errToken != nil {
			return nil, fmt.Errorf("crowdsecQuery:renewToken url:%s %w", stringURL, errToken)
		}
		return c.crowdsecQuery(stringURL, nil)
	}
```

`data` is discarded, so a POST retried after a token renewal is reissued as a GET. Replay the
original body. Guard against unbounded recursion: a second 401 must not retry forever.

## Deliverable 4: response body leaked on reverse-proxy statuses

```209:217:pkg/lapi/client_http.go
	res, err := current.httpClient.Do(req)
	if err != nil || isReverseProxyError(res.StatusCode) {
		return nil, fmt.Errorf("crowdsecQuery:unreachable url:%s %w", stringURL, err)
	}
	defer func() {
		if err = res.Body.Close(); err != nil {
			c.log.Error("crowdsecQuery:closeBody " + err.Error())
		}
	}()
```

The `defer` is installed *after* the early return. When `err == nil` and the status is 502, 503 or
504 (`isReverseProxyError`, `pkg/lapi/client_http.go:114-118`) the function returns with the body
never closed, so the connection cannot be reused. Exactly the class of bug #70 fixes on the AppSec
side; look at how #70 words and tests its drain before choosing an approach here, so the two stay
consistent.

Note for your own analysis: there is **no** nil-pointer bug on that line. `||` short-circuits, so
`res.StatusCode` is only evaluated when `err == nil`, where `net/http` guarantees a non-nil response.
A previous review claimed a panic risk here and was wrong. Do not "fix" a nil dereference that does
not exist, and do not add a redundant `res == nil` guard unless you can show a path that reaches it.

## Deliverable 5: `%w` wrapping a nil error in the same branch

In that same early return, when the trigger is the reverse-proxy status rather than a transport
error, `err` is nil and gets wrapped with `%w`. The operator-facing message becomes a literal
`crowdsecQuery:unreachable url:... %!w(<nil>)`. Make the two cases produce accurate messages, and
include the status code when the status is what failed. Assert the message text in a test, since the
whole point is operator legibility.

## Constraints

Yaegi v0.16.1 is what Traefik v3.7.1 bundles, so the Go 1.22 stdlib is the ceiling and these are
unavailable: `atomic.Bool`, `atomic.Int64`, `atomic.Pointer[T]`, and anything newer than 1.22. Follow
the existing pattern of `int64` fields with `sync/atomic` free functions. `errors.Join` exists in
1.20 but check how this package already aggregates errors before introducing a new idiom. Keep
`Client.mu` off the HTTP path: it guards lifecycle state and the live header-scope registry, and
nothing may hold it across a LAPI call.

## Gates, all required before opening the PR

Run in a dedicated worktree, `D:/repositories/wt-modsec-<key>`. The main checkout at
`D:/repositories/crowdsec-bouncer-traefik-plugin` must stay on `master` and must not be disturbed: it
holds the owner's uncommitted files. Never run `git checkout`, `git switch`, `git stash` or
`git reset` there.

- `go build ./...`
- `go vet ./...`
- `go test ./pkg/... -count=1`
- `go test . -count=1` (about 50s, this is the yaegi/e2e package)
- `golangci-lint run ./...` — needs `C:\Program Files\Git\usr\bin` prepended to `PATH`, otherwise
  `goimports` fails with `exec: "diff": executable file not found`
- Race detector. This host has no C compiler, so use Docker (29.1.5 is installed):
  `docker run --rm -v ${PWD}:/src -w /src -e CGO_ENABLED=1 golang:1.22.12 go test -race -count=1 ./pkg/...`
  CI also has a `Race detector` job now, added by #72, but do not use CI as your first signal.

Use `-count=1` everywhere so cached results cannot pass for a run.

Merge `origin/master` into the branch before opening the PR and re-run every gate on the merged tree.
A PR's CI runs against the base recorded when it was opened, so a green check on a stale base proves
nothing. Gotcha: untracked `devstate/` copies from other tickets can block the merge; remove the
untracked copies rather than committing them.

## Do not merge

Open the PR and stop. The owner merges. Say explicitly in the PR body that deliverable 1 changes
runtime behavior for existing deployments and needs owner ratification, and list the behavior matrix
above so the owner can check the policy rather than the code.
