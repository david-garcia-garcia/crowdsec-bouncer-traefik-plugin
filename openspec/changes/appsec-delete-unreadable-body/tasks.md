## 1. AppSec query

- [ ] 1.1 Remove `http.MethodDelete` from `isMethodWithBody` in `pkg/appsec/query.go`
- [ ] 1.2 Add `Test_appsecQuery_unreadableBodyDeleteNotDropped` mirroring `Test_appsecQuery_unreadableBodyGetNotDropped` (HTTP/3, `ContentLength < 0`, blocking body, `FailureActionBan` must not error)

## 2. Spec and usage

- [ ] 2.1 Keep the change delta on `core_plugin_appsec_failure-action` (DELETE not in the unreadable-body drop set)
- [ ] 2.2 If `knowledge/devdocs/core_plugin_appsec.md` needs a DELETE gotcha, add it there; do not create a second AppSec packet
