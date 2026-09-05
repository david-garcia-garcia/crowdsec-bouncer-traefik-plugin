# Code review
pin: origin/master...HEAD
change: crowdsec-connection-bouncer-split

## Standards
1. [hard] Leave a trail — `version.go` (deleted) / `pkg/crowdsecconnection/connection.go:42` — `version.go` and `pluginVersion` are removed but `.github/workflows/release-prepare.yml` and `release-publish.yml` still `sed` `pluginVersion` in `version.go`; the new `Version` const drops the “Do not edit by hand: Release workflow bumps it” note
 → Restore a root `version.go` shim or repoint the release workflows at `crowdsecconnection.Version` and carry the bump comment forward

2. [hard] Leave a trail — `pkg/crowdsecconnection/connection.go:261` — `startStream` logs `"New:getToken "` after stream startup was extracted out of `New`
 → Rename the prefix to `startStream:getToken` (or `CrowdsecConnection:getToken`)

3. [hard] Leave a trail — `pkg/crowdsecconnection/connection.go:142` — Appsec key resolution failure is logged as `"Prepare:crowdsecLapiKey fail to get CrowdsecAppsecKey..."`
 → Use a Prepare-scoped prefix that names AppsecKey, not LAPI key

4. [hard] Leave a trail — `pkg/crowdsecconnection/connection.go:433` — `handleNoStreamCache` emits `"handleStreamCache:unknownType "` on unknown decision types
 → Change the log prefix to `handleNoStreamCache:unknownType`

5. [hard] Leave a trail — `pkg/bouncer/bouncer.go:116` — godoc still says `ServeHTTP principal function of plugin` though `Bouncer` is now the per-router handler and `plugin.New` is the Traefik entry
 → Reword to “per-router middleware handler” (or similar)

6. [hard] Leave a trail — `pkg/bouncer/bouncer.go:184` — `ServeHTTP` calls `conn.LiveLookup` but logs `"handleNoStreamCache:crowdsecQuery "`
 → Log under `ServeHTTP:LiveLookup` (or drop the stale `handleNoStreamCache` prefix)

7. [hard] Leave a trail — `pkg/bouncer/bouncer.go:42` — `New` godoc cites `(ForRoute)`, which is not a symbol in this tree
 → Remove the insider nickname; say “per-router handler bound to conn”

8. [hard] Leave a trail — `pkg/crowdsecconnection/connection.go:255` — new `startStream` helper has no job comment after stream startup moved out of `New`
 → Add a one-line godoc: starts stream ticker / initial poll for stream and alone modes

9. [hard] Leave a trail — `pkg/crowdsecconnection/identity.go:50` — new `identityFrom` builds the reclaim-key payload but has no job comment (unlike `identity` above it)
 → Add a one-line godoc: maps `configuration.Config` into reclaim identity fields

10. [hard] Leave a trail — `pkg/cache/cache.go:30` — edited `localCache` now owns a per-client `*ttl_map.Heap` but the type has no job comment explaining isolation
 → Add a one-line type comment: per-`Client` in-memory TTL store

11. [hard] Name for the scope — `pkg/bouncer/bouncer.go:53` — `b := &Bouncer{` uses a single-letter placeholder where the role is the per-router handler under construction
 → Rename to `routeHandler` or `handler`

12. [judgement] Duplicated Code — `pkg/crowdsecconnection/connection.go:427` and `pkg/crowdsecconnection/connection.go:513` — the ban/captcha/default switch on `decision.Type` appears in both `handleNoStreamCache` and `handleStreamCache`
 → Extract one `decisionRemediation(decision Decision) string` helper used by both paths

## Spec
none

## Security
none

## Performance
none

Standards: 12 findings, worst: Leave a trail at deleted `version.go` / release workflows
Spec: 0 findings, worst: none
Security: 0 findings, worst: none
Performance: 0 findings, worst: none

## Applied
- Standards 1: moved `Version` to `pkg/crowdsecconnection/version.go` with bump comment; release-prepare/publish sed that file
- Standards 2: `startStream:getToken`
- Standards 3: `Prepare:crowdsecAppsecKey`
- Standards 4: `handleNoStreamCache:unknownType`
- Standards 5: ServeHTTP godoc is “per-router middleware handler”
- Standards 6: `ServeHTTP:LiveLookup` (and the sibling live-lookup cache-hit log)
- Standards 7: New godoc drops `(ForRoute)`
- Standards 8: startStream job comment
- Standards 9: identityFrom job comment
- Standards 10: localCache type comment
- Standards 11: `routeHandler` in `bouncer.New`

## Recorded and skipped
- Standards 12: judgement Duplicated Code — same Type switch in stream vs live; not a commandment; left as two call sites
