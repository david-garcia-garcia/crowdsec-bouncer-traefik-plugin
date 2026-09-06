# Standards

1. [hard] Symmetry and consistency — `pkg/appsec/query_test.go:93-116` — `Test_appsecQuery_unreadableBodyQueriesHeadersOnlyUnderBan` captures `gotMethod` and asserts AppSec received GET, but sibling `Test_appsecQuery_streamingDoesNotBlock` (lines 69–90) uses the same `newStreamingRequest` unreadable-body path without that assertion even though failure action no longer affects request build
   → Add the same `gotMethod` / GET assertion to `Test_appsecQuery_streamingDoesNotBlock` (or extract a shared helper both tests call)
   Status: done
   Argument: fa9d177 — `Test_appsecQuery_streamingDoesNotBlock` now asserts AppSec GET via `gotMethod`.
