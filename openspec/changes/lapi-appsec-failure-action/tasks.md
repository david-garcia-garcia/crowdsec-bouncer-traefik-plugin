## 1. Config

- [ ] 1.1 Add `LapiFailureAction` and `AppsecFailureAction` to `Config` (`json:"lapiFailureAction"` / `appsecFailureAction"`), defaults `ban`, validate `passthrough|ban|captcha`, reject `captcha` without a captcha provider
- [ ] 1.2 Remove `CrowdsecAppsecFailureBlock`, `CrowdsecAppsecUnreachableBlock`, and `CrowdsecAppsecUnreadableBodyBlock` from `Config` and all test fixtures that set them
- [ ] 1.3 Put the three action string constants next to the other config enums

## 2. Connection

- [ ] 2.1 Add `LapiFailureAction` to reclaim identity
- [ ] 2.2 Change `AppsecPolicy` to a single failure action; map 500 / unreachable / unreadable body onto that action (`passthrough` → allow or headers-only GET; `ban` → error)
- [ ] 2.3 Stop returning `BannedValue` on live LAPI HTTP/parse error; surface the error so ServeHTTP can apply `LapiFailureAction`
- [ ] 2.4 Keep `UpdateMaxFailure` / `StreamHealthy` as today

## 3. Bouncer

- [ ] 3.1 Stream/alone unhealthy cache miss: apply `LapiFailureAction` (`passthrough` → pass path, `ban` → tech ban, `captcha` → captcha client)
- [ ] 3.2 Live lookup error: same `LapiFailureAction` dispatch
- [ ] 3.3 AppSec query error / captcha fallback: apply `AppsecFailureAction` without treating AppSec JSON `captcha` as `pkg/captcha`
- [ ] 3.4 Store `AppsecFailureAction` on Bouncer; do not put it on CrowdsecConnection identity

## 4. Docs and tests

- [ ] 4.1 README + examples: document the two keys, **BREAKING** removal of the three bools, keep `updateMaxFailure`
- [ ] 4.2 Unit tests for validate, live error passthrough/ban, stream unhealthy miss, AppSec 500/unreachable/unreadable body
- [ ] 4.3 Update mock e2e AppSec yaml that set the old bools
