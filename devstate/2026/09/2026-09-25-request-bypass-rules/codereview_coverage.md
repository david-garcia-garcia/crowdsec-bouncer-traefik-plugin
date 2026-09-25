# Test coverage

1. [hard] Critical path untested — `pkg/bouncer/bouncer.go:487` — LAPI match must skip missing-subscribed-LAPI failure; no test fails if Match moves after the unbound-LAPI ban
   Quote:
      ```
      if b.lapiBypassRules.Match(req.Request) {
          b.passOrForcedCaptcha(rw, req)
          return
      }
      if b.subscribeLAPI && lapiClient == nil {
          b.applyLapiFailureAction(rw, req, configuration.ReasonLAPI, lapi.OriginPluginLapiFailure)
      TestServeHTTP_lapiBypassSkipsStreamStoreAndUnhealthy binds a client; TestServeHTTP_UnboundLAPIUsesFailureAction has no bypass. (none)
      ```
   Fix: Assert a matching LAPI bypass with subscribeLAPI set and loaded LAPI nil (startupBlock false) reaches next and does not apply the LAPI failure action
   Status: done
   Argument: Added `TestServeHTTP_lapiBypassSkipsUnboundLAPIFailure` in `pkg/bouncer/zzz_bypass_rules_test.go`.
2. [hard] Edge case untested — `pkg/httprule/set.go:160` — set predicates AND; no test fails if method-or-path becomes OR
   Quote:
      ```
      if !rule.matchMethod(httpReq.Method) { return false }
      if rule.pathRe != nil && !rule.pathRe.MatchString(path) { return false }
      TestNew_methodOnly is method-only; TestMatch_unanchoredPath is path-only; TestMatch_headerAndAndEmptyPresent is headers-only. (none)
      ```
   Fix: Assert `{method: "^GET$", path: "^/healthz$"}` does not match GET `/other`
   Status: done
   Argument: Added `TestMatch_methodAndPathAreAnd` in `pkg/httprule/zzz_httprule_test.go`.
3. [judgement] Happy path only — `pkg/httprule/set.go:213` — empty cookie pattern means present; untested
   Quote:
      ```
      if predicate.pattern == nil {
          continue
      }
      TestMatch_headerAndAndEmptyPresent covers headers; TestMatch_cookieNamesAreCaseSensitive uses `^[a-f0-9]+$`. (none)
      ```
   Fix: Assert `{cookies: {session: ""}}` matches a present `session` cookie and misses when that name is absent
   Status: skipped
   Argument: judgement; empty-present is already proven for headers.
