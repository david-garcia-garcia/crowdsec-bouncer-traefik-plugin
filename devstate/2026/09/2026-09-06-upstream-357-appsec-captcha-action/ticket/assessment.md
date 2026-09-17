# Assessment: upstream#357

- relevant: yes
- kind: feature
- affected: yes
- status: present-fixed-unproven
- proof: none
- recommended-action: add-tests
- slug: 2026-09-06-upstream-357-appsec-captcha-action
- rationale: Upstream asks for AppSec JSON `action: captcha` (reading the response body, not only the status code). On master, `pkg/appsec/query.go` caps and parses the AppSec envelope (`action`, `http_status`, `user_body_content`, cookies, headers) and defines `ActionCaptcha`; `Bouncer.applyAppsecServeHTTP` relays any non-allow/non-ban action (including captcha) through `handleAppsecResponseServeHTTP`, distinct from `pkg/captcha` used for LAPI or failure-action captcha. Challenge relay is tested end-to-end in the bouncer, but no unit test asserts `{"action":"captcha",...}` parsing or relay.

## Evidence
- current: pkg/appsec/query.go, pkg/bouncer/bouncer.go, knowledge/devdocs/core_plugin_appsec.md
- tests: pkg/appsec/query_test.go (challenge JSON only), pkg/bouncer/bouncer_test.go (challenge relay only)
