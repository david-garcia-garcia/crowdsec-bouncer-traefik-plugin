# Devdocs impact
change: lapi-ban-retry-after

## Units
- Ban page `Retry-After` (LAPI ban answered 429) — pattern — `pkg/bouncer/bouncer_serve_remediation.go` (`handleBanStatusServeHTTP`, `retryAfterSeconds`, `noLAPIDecisionEnd`)
- Decision time left through remediation dispatch — pattern — `pkg/bouncer/bouncer_serve_lapi.go` → `remediateUnderActionRules` → `handleRemediationServeHTTP` → `handleCaptchaKindServeHTTP` / `handleBanServeHTTP`
- DecisionStore decision time left (12-byte `LiveSlot`, Redis slot value end line, `Store.LookupRemediation` return) — subsystem — `pkg/decisionstore/`; spec `core_plugin_decisionstore_store`
- Stream apply decision duration — subsystem — `pkg/lapi/client_decisions.go` (`streamPutItem`); spec `core_plugin_lapi_stream-apply`
- Live lookup time left (`LiveLookup` return, `memoLive` decision duration) — subsystem — `pkg/lapi/client_live.go`, `pkg/lapi/client_decisions.go`; spec `core_plugin_decisions_scopes`

Skipped (pack: tests and fixtures): `pkg/*/zzz_*_test.go`, `tests/e2e/mock/**` (helpers `response_header`, `assert_header_int_between`, `assert_header_absent`; `/retry` routers; mock Redis 4-line value for 1.2.3.7), `tests/e2e/real/**`. The two e2e packets were still read for usage that the new fixtures make wrong.

## Findings
- [x] stale-usage  DecisionStore — `core_plugin_decisionstore`: Key files missed `liveslot.go` and `lookup.go` (homes of `LiveSlot.DecisionEnd` and `lookupHit.decisionLeft` / `mergeLookupHit`, which the packet's Language names); Language `Packed word` carried ticket scratch ("grown from 8 …, approved in <IssueKey>")
- [x] stale-usage  DecisionStore lookup return — `core_plugin_decisionscope`: snippet destructured four values from `LookupRemediation`; gotcha said Redis Ip/header values are `KindOriginString` (they are the Redis slot value with scenario and end)
- [x] stale-usage  DecisionStore lookup return — `core_plugin_lapi_usage-metrics`: snippet destructured four values; How-to said Redis Ip/header persist origin via `KindOriginString`
- [x] stale-usage  Decision time left through remediation dispatch — `core_plugin_lapi_origin-based-decision-remap`: snippet destructured four values; nothing said the time left passes `appliedLAPIRemediation` unchanged
- [x] stale-usage  Live lookup time left — `core_plugin_lapi_connection`: snippet `value, err := client.LiveLookup(...)` (wrong before this change, now four returns); no word on the `decisionLeft` return or the memo's `DecisionDurationSec`
- [x] stale-usage  Decision time left through remediation dispatch — `core_plugin_middleware_action-rules`: snippet called `handleRemediationServeHTTP` without the new `decisionLeft` argument; action-rule ban passes `noLAPIDecisionEnd`
- [x] stale-usage  Decision time left through remediation dispatch — `core_plugin_middleware_captcha-routing`: caller-passes bullet did not name the `decisionLeft` argument a downgrade ban forwards
- [x] stale-usage  Real-stack e2e — `build_e2e_real`: gotcha named one file-provider stream bouncer key (`BOUNCER_KEY_TRAEFIK_SCOPES`); `retry-after.yml` adds `BOUNCER_KEY_RETRY_AFTER_STREAM`; extra whoami routes list lacked `/retry-after-stream`

Checked, none:
- `core_plugin_middleware_ban-page` — implement wrote the header rule, the `noLAPIDecisionEnd` caller list, the snippet, and the serveLAPI-leak gotcha; matches `bouncer_serve_remediation.go`.
- `core_plugin_lapi_stream-apply` — `streamPutItem` sets `DurationSec` and `DecisionDurationSec` to the parsed duration; Range upserts carry no end. Matches code.
- `core_plugin_decisionstore` Language `Redis slot value` / `Decision time left` — match `redis_pack.go` (`packToString`, `splitScenarioEnd` at the last newline) and `redis.go` / `liveslot.go` lookup.
- `core_plugin_lapi_query-round-trip`, `core_plugin_middleware`, `core_plugin_appsec`, `std_go_logger_debug-attrs`, `build_e2e_go-redis`, `build_e2e_mock` — no usage this apply makes wrong (Trace stems unchanged; go-redis test only gained local helpers; mock packet never described the Redis stand-in or helper names).
- README — `bouncerRemediationStatusCode` paragraph and the `ban` row match the apply. The stream-mode "around 20 MB" line was not re-measured; its basis is not in the repo, and the 4 extra bytes per slot add about 7 MB only at 400k decisions (`memory_pack.go` table).
