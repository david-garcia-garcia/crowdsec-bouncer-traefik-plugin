## 1. Config and Policy

- [x] 1.1 Add `CrowdsecAppsecUnreadableBodyBlock bool` to `Config` (`json:"crowdsecAppsecUnreadableBodyBlock,omitempty"`) and set `New()` default false
- [x] 1.2 Add `UnreadableBodyBlock` to `appsec.Policy`; copy from config in `bouncer.New` and pass it in `applyAppsecServeHTTP`

## 2. Query

- [x] 2.1 Restore DestBranch `isMethodWithBody` (POST, PUT, PATCH, DELETE)
- [x] 2.2 Pass `Policy` into `newAppsecForwardRequest` / `newAppsecBodyRequest`; when `isBodyUnreadable` and `UnreadableBodyBlock` and `isMethodWithBody`, return `appsecQuery:unreadableBody dropped` without calling AppSec; otherwise headers-only GET

## 3. Tests and docs

- [x] 3.1 Keep headers-only coverage for default-false streaming POST under `FailureActionBan` (no hang, AppSec GET)
- [x] 3.2 Add tests: true + unreadable POST drops and does not call AppSec; true + unreadable GET still GET; true + `FailureActionPassthrough` still drops POST
- [x] 3.3 README: document `CrowdsecAppsecUnreadableBodyBlock` (default false); stop saying FailureAction replaces that bool
- [x] 3.4 Update `knowledge/devdocs/core_plugin_appsec.md` usage for the bool
