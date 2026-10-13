# Nitpicks

1. [hard] Clear conditions — `pkg/bouncer/bouncer.go:296` — `if !subscribeLAPI || lapiClient == nil` is the complement of “subscribed and bound”; the body is two named cases (missing subscribed LAPI vs LAPI off)
   ```
   if !b.subscribeLAPI || lapiClient == nil {
   	if b.subscribeLAPI && lapiClient == nil {
   		b.applyLapiFailureAction(rw, req, configuration.ReasonLAPI, lapi.OriginPluginLapiFailure)
   		return
   	}
   	b.passOrForcedCaptcha(rw, req)
   	return
   }
   ```
   → Guard `subscribeLAPI && lapiClient == nil` (failure action), then `!subscribeLAPI` (pass or forced captcha)
   Status: done
   Argument: two left-margin guards; subscribeEmpty renamed announceEmptyBind.
2. [hard] Linear coding — `pkg/bouncer/bouncer.go:296` — those two cases sit under the complement gate instead of early returns; the main path is the fall-through after the nest
   ```
   if !b.subscribeLAPI || lapiClient == nil {
   	if b.subscribeLAPI && lapiClient == nil {
   		b.applyLapiFailureAction(...)
   		return
   	}
   	b.passOrForcedCaptcha(rw, req)
   	return
   }
   ```
   → Two guard clauses at the left margin; then the live/stream/alone lookup
   Status: done
   Argument: two left-margin guards; subscribeEmpty renamed announceEmptyBind.
3. [hard] Name for the scope — `pkg/instance/tables.go:264` — `subscribeEmpty` is the Subscribe call-site situation, not the role this body uses (announce empty bind / do not skip an unchanged Store)
   ```
   func storeValue(..., subscribeEmpty bool) {
   	if isNilClient(client) && named.empty == nil {
   		if subscribeEmpty && sub.Log != nil { /* log unbound */ }
   		return
   	}
   	if !changed && !subscribeEmpty {
   		return
   	}
   }
   ```
   → Rename to the role (`announceEmptyBind` or `forceEmptyAnnounce`)
   Status: done
   Argument: two left-margin guards; subscribeEmpty renamed announceEmptyBind.
