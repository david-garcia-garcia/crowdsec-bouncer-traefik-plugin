# Nitpicks

1. [hard] Clear conditions — `pkg/ratelimit/charge.go:66` — `if !allowed` appends to `verdict.Exceeded` (log buckets) only because the deny branch above returned; the reader must know the bucket action enum to see that this is the log-bucket case
   Fix: `if !allowed && bucket.action == ActionLog` (compileBucketAction at `pkg/ratelimit/bucket_set.go:118` only yields ActionDeny or ActionLog, so behaviour is unchanged)
   Status: done
   Argument: `charge.go`: `if !allowed && bucket.action == ActionLog`.
   Quote:
   ```go
   if !allowed && bucket.action == ActionDeny {
       verdict.DenyBucket = bucket.name
       verdict.RetryAfter = retryAfterAt(set.now(), bucket.window)
       return verdict
   }
   if !allowed {
       verdict.Exceeded = append(verdict.Exceeded, ExceededBucket{Name: bucket.name, Requests: bucket.requests, Window: bucket.window})
   }
   ```
2. [hard] Name for the scope — `pkg/ratelimit/zzz_yaegi_test.go:40` — the interpreted program's helper is named `fail`, a mood verb; its job is to print the message and exit the program with status 1
   Fix: Rename to `exitWithFailure` (or `printAndExit`) and update its call sites in `main`
   Status: done
   Argument: Yaegi program helper renamed `exitWithFailure`, five call sites updated.
3. [hard] Linear coding — `pkg/ratelimit/key.go:34` — `queryValues` nests the parse under `if !source.queryParsed` and again under `if source.httpReq.URL != nil`, returning at the bottom
   Fix: Guard `if source.queryParsed { return source.query }`; set `queryParsed`; guard `if source.httpReq.URL == nil { return nil }`; then parse and return at the left margin
   Status: done
   Argument: `queryValues` uses early-return guards; parse at the left margin.
   Quote:
   ```go
   func (source *keySource) queryValues() url.Values {
       if !source.queryParsed {
           source.queryParsed = true
           if source.httpReq.URL != nil {
               source.query = source.httpReq.URL.Query()
           }
       }
       return source.query
   }
   ```
4. [judgement] Name for the scope — `pkg/bouncer/remediation_header.go:52` — `headerThirdField` and the local `third` (line 44) name the value by its position in `kind:reason:third`, not by its role (the reason's detail: encoded metrics origin for lapi, bucket name for ratelimit)
   Fix: Rename to `headerReasonDetail` and the local to `detail`
   Status: skipped
   Argument: judgement: cosmetic rename across the header helper and its tests; the doc comment already states the role per reason.
5. [judgement] Linear coding — `pkg/httprule/set.go:131` — the edited gate prepends `!allowCatchAll` to five clauses that are one concept (every predicate is any), so the reader re-derives "catch-all rule" from the clause list
   Fix: `matchesEveryRequest := methodAny && pathRe == nil && hostRe == nil && len(headers) == 0 && len(cookies) == 0`, then `if matchesEveryRequest && !allowCatchAll`
   Status: skipped
   Argument: judgement: the five clauses predate this change, which only added the flag; outside the lines this ticket owns.
   Note:
   ```
   The five clauses predate this change; the diff only added !allowCatchAll to that line.
   ```
