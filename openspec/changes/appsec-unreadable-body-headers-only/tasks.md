## 1. AppSec query

- [ ] 1.1 In `newAppsecBodyRequest`, when `isBodyUnreadable`, always build a headers-only GET; do not return `appsecQuery:unreadableBody dropped` for methods with a body
- [ ] 1.2 Keep `CrowdsecAppsecFailureAction` mapping for 500 / unreachable / captcha on that GET; do not change `New()` default `ban`

## 2. Tests and docs

- [ ] 2.1 Change `Test_appsecQuery_dropUnreadableBody` so a streaming POST under `FailureActionBan` returns no error within 2s and AppSec is called with GET
- [ ] 2.2 Keep `Test_appsecQuery_streamingDoesNotBlock` and GET unreadable coverage
- [ ] 2.3 Update README `CrowdsecAppsecFailureAction` so unreadable HTTP/2+ bodies are headers-only, not a ban drop
- [ ] 2.4 Update `knowledge/devdocs/core_plugin_appsec.md` usage: unreadable body is not a failure-action drop
