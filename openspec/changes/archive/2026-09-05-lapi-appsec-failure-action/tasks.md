## 1. Config

- [x] 1.1 Add `CrowdsecLapiFailureAction` and `CrowdsecAppsecFailureAction` to `Config` (`json:"crowdsecLapiFailureAction"` / `crowdsecAppsecFailureAction"`), defaults `ban`, validate `passthrough|ban|captcha`, reject `captcha` without a captcha provider
- [x] 1.2 Remove `CrowdsecAppsecFailureBlock`, `CrowdsecAppsecUnreachableBlock`, and `CrowdsecAppsecUnreadableBodyBlock` from `Config` and all test fixtures that set them
- [x] 1.3 Put the three action string constants next to the other config enums

## 2. Connection

- [x] 2.1 Add `CrowdsecLapiFailureAction` to reclaim identity
- [x] 2.2 Change `AppsecPolicy` to a single failure action; map 500 / unreachable / unreadable body onto that action (`passthrough` → allow or headers-only GET; `ban` → error)
- [x] 2.3 Stop returning `BannedValue` on live LAPI HTTP/parse error; surface the error so ServeHTTP can apply `CrowdsecLapiFailureAction`
- [x] 2.4 Keep `UpdateMaxFailure` / `StreamHealthy` as today

## 3. Bouncer

- [x] 3.1 Stream/alone unhealthy cache miss: apply `CrowdsecLapiFailureAction` (`passthrough` → pass path, `ban` → tech ban, `captcha` → captcha client)
- [x] 3.2 Live lookup error: same `CrowdsecLapiFailureAction` dispatch
- [x] 3.3 AppSec query error / captcha fallback: apply `CrowdsecAppsecFailureAction` without treating AppSec JSON `captcha` as `pkg/captcha`
- [x] 3.4 Store `CrowdsecAppsecFailureAction` on Bouncer; do not put it on CrowdsecConnection identity

## 4. Docs and tests

- [x] 4.1 README + examples: document the two keys, **BREAKING** removal of the three bools, keep `updateMaxFailure`
- [x] 4.2 Unit tests for validate, live error passthrough/ban, stream unhealthy miss, AppSec 500/unreachable/unreadable body
- [x] 4.3 Update mock e2e AppSec yaml that set the old bools
