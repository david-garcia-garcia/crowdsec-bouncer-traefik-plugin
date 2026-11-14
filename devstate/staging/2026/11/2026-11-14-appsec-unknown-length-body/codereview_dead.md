# Dead

1. [hard] Dead branch or constant — `pkg/bouncer/remediation_header.go:67` — the new `case lapi.OriginPluginAppsecBodyTimeout` in `headerReasonFromOrigin` is reached only by `TestHeaderReasonFromOrigin`; the single production emitter (`bouncer.go:467`) passes `headerReasonAppsecBodyTimeout` straight to `handleBanServeHTTP` and never routes the origin through the mapper, and no production caller of `headerReasonFromOrigin` (`bouncer.go:317`, `:400`, `:433`) is ever handed this origin
   Quote:
   ```
   +	case lapi.OriginPluginAppsecBodyTimeout:
   +		return headerReasonAppsecBodyTimeout
   ```
   Note:
   ```
   grep OriginPluginAppsecBodyTimeout over *.go, tests dropped: client_metrics.go:29 (definition), bouncer.go:467 (direct handleBanServeHTTP), remediation_header.go:67 (this case). Callers of headerReasonFromOrigin get lapi_failure, tech_streamfail, rules:*, appsec_failure, or a LAPI decision origin. Same pattern as OriginPluginTechCacheFail, which also bypasses the mapper and has no case.
   ```
   Fix: Delete the case and its `zzz_remediation_header_test.go` table row; the header stays asserted by the bouncer body-timeout test through `handleBanServeHTTP`
   Status: done
   Argument: Deleted the `OriginPluginAppsecBodyTimeout` case in `headerReasonFromOrigin` and its table row; design.md and tasks.md 4.1 now say the ban passes the reason directly (header still asserted by the bouncer body-timeout tests).
2. [judgement] Test-only new symbol — `pkg/appsec/zzz_test_helpers.go:76` — `newUnknownLengthRequest` is added to a file without the `_test.go` suffix and without a build tag, so it compiles into the plugin package (Yaegi included); every caller is a `zzz_*_test.go` file. Judgement because the file name marks it a test-helper file by repo convention and its older helpers share the same placement
   Quote:
   ```
   +// newUnknownLengthRequest is an HTTP/2 request whose body has no declared length (no Content-Length).
   +func newUnknownLengthRequest(method string, body io.Reader) *http.Request {
   ```
   Note:
   ```
   grep newUnknownLengthRequest over *.go: definition at zzz_test_helpers.go:76; callers only in zzz_body_read_timeout_test.go and zzz_query_test.go. pkg/appsec has no //go:build lines.
   ```
   Fix: Move `newUnknownLengthRequest` into a `pkg/appsec/zzz_*_test.go` file (or rename the helper file to `zzz_test_helpers_test.go` if no non-test file depends on it)
   Status: skipped
   Argument: judgement; `zzz_test_helpers.go` is the package helper file by repo convention and already holds the other request helpers; not applied unattended.
