# Test coverage

1. [hard] Edge case untested — `pkg/lapi/client.go:189` — live Close closes the Gate; no test that a later lookup is denied (`core_plugin_lapi_backend-backoff` Close scenario)
   → After `Close`, `LiveLookup` must not hit LAPI and must return `queryLiveDecisions:skipped`
   Status: done
   Argument: 9661262 added `TestLiveLookup_CloseDeniesLaterAllow`.
2. [hard] Edge case untested — `pkg/appsec/client.go:77` — AppSec Close closes the Gate; no test that a later Query is denied (`core_plugin_appsec_backend-backoff` Close scenario)
   → After `Close`, `Query` must not hit AppSec and must apply FailureAction with `appsecQuery:skipped`
   Status: done
   Argument: 9661262 added `TestQuery_CloseDeniesLaterAllow`.
3. [hard] Edge case untested — `pkg/lapi/client_decisions.go:136` — parse error Reports failure; no test would fail if that Report flipped to success
   → Invalid JSON body must trip the Gate so the next `LiveLookup` does not hit LAPI
   Status: done
   Argument: 9661262 added `TestLiveLookup_ParseErrorReportsFailure`.
4. [hard] Edge case untested — `pkg/lapi/client_decisions.go:150` — duration-parse Reports failure; no test would fail if that Report flipped to success
   → Ban body with an unparseable duration must trip the Gate so the next `LiveLookup` does not hit LAPI
   Status: done
   Argument: 9661262 added `TestLiveLookup_DurationParseReportsFailure`.
5. [hard] Edge case untested — `pkg/appsec/query.go:160` — `errAppsecReadBody` Reports success; existing `Test_appsecQuery_failureActionOnResponseBodyReadError` uses a nil Gate
   → Admitted read-body io must Report success so the next `Query` still hits AppSec
   Status: done
   Argument: 9661262 added `TestQuery_ReadBodyReportsSuccess`.
6. [hard] Critical path untested — `pkg/appsec/query.go:134` — denied Allow with `passthrough` is a named FailureAction path; tests only cover ban skip
   → After the Gate trips, `Query` with passthrough must allow and must not hit AppSec
   Status: done
   Argument: 9661262 added `TestQuery_DeniedPassthroughDoesNotHitAppSec`.
7. [hard] Edge case untested — `pkg/lapi/client.go:144` — none mode is in the construct-Gate branch; tests only assert live
   → `OpenLive` with `crowdsecMode: none` must own a Gate
   Status: done
   Argument: 9661262 `TestOpen_LiveHasGateStreamDoesNot` now asserts none owns a Gate.
8. [judgement] Happy path only — `pkg/lapi/client_decisions.go:158` — captcha answer Reports success on the same arm as ban/none; no captcha-specific Report test
   → Same success Report path; skip a dedicated captcha fixture
   Status: skipped
   Argument: judgement; captcha uses the same success Report arm as ban/none.
