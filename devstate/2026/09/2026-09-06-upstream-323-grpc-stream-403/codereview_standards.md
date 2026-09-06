# Standards

## Identifier walk (Name for the scope)

| Identifier | Introduced / retargeted | Role in body | Verdict |
|------------|-------------------------|--------------|---------|
| `CrowdsecAppsecUnreadableBodyBlock` | introduced (`Config`) | per-router bool; true drops unreadable POST/PUT/PATCH/DELETE before AppSec | pass — spells job; matches lua mirror naming |
| `UnreadableBodyBlock` | introduced (`appsec.Policy`) | same knob inside `Query` / `newAppsecBodyRequest` | pass — role in Policy scope; pairs with `FailureAction` |
| `appsecUnreadableBodyBlock` | introduced (`Bouncer`) | per-router copy wired into `applyAppsecServeHTTP` | pass — matches `appsecFailureAction` / `appsecEnabled` stem |
| `isBodyUnreadable` | retargeted (+ comment) | HTTP/2+ body with no finite length | pass |
| `isMethodWithBody` | restored (+ comment) | methods that may carry a body toward AppSec | pass |
| `resultForFailureActionErr` | removed | thin wrapper dropped with unreadable drop retarget | pass — consume before produce |
| `Test_appsecQuery_unreadableBodyQueriesHeadersOnlyUnderBan` | renamed | ban + unreadable POST must headers-only GET | pass |
| `Test_isMethodWithBody` | introduced | table-driven method coverage | pass |
| `Test_appsecQuery_unreadableBodyDroppedWhenBlock` | introduced | true bool drops before AppSec | pass |
| `Test_appsecQuery_unreadableBodyGetNotDroppedWhenBlock` | introduced | true bool still GET-exempts GET | pass |
| `Test_appsecQuery_unreadableBodyDroppedWhenBlockDespitePassthrough` | introduced | bool independent of failure action | pass |
| `gotMethod`, `appsecCalled`, `finished` | introduced (test locals) | capture AppSec method / call / async result | pass |
| `decisionscope.NoBannedValue` | retargeted (merge import) | stream lease sentinel after dest merge | pass — uses package owner |

Usage-doc Gotchas (`core_plugin_appsec.md` **Do**): unreadable body split from failure action; 502/503/504 stay unreachable; drop path uses plain error not `ErrFailureCaptcha`. No **Do** breach.

1. [hard] Leave a trail — `pkg/appsec/query.go:143-148` — unreadable-body case has two branches; headers-only path has a block intro, drop path does not, and the drop no longer consults `FailureAction` (behavior change from removed `resultForFailureActionErr`)
   ```go
   case isBodyUnreadable(httpReq):
       if pol.UnreadableBodyBlock && isMethodWithBody(httpReq.Method) {
           return nil, errors.New("appsecQuery:unreadableBody dropped")
       }
       // HTTP/2+ streams have no finite body to copy; inspect headers only (issue #323).
   ```
   → Add a one-line comment on the drop branch (e.g. independent of `FailureAction`)
   Status: done
   Argument: aa21891 — drop branch comment: independent of CrowdsecAppsecFailureAction.

2. [judgement] Smallest durable delta — `pkg/configuration/configuration.go:158-1141`, `pkg/bouncer/bouncer.go:21-67` — adding one config field and one bouncer field re-aligns entire `New()` literals and struct field columns
   → Limit diff to the new field lines; leave sibling entries at prior alignment
   Status: skipped
   Argument: gofmt realigns the composite when a longer field is added; reverting would fail gofmt/CI.

3. [judgement] Symmetry and consistency — `pkg/appsec/query_test.go:134-156` vs `851-880` — new `Test_appsecQuery_unreadableBodyGetNotDroppedWhenBlock` captures `gotMethod` and asserts AppSec GET; sibling `Test_appsecQuery_unreadableBodyGetNotDropped` (same GET exemption, default false bool) still omits that assertion though POST siblings now both assert GET
   → Add the same `gotMethod` / GET assertion to `Test_appsecQuery_unreadableBodyGetNotDropped`
   Status: skipped
   Argument: judgement; GET exemption under default false already has a no-error test; the new sibling covers the bool-true GET path.
