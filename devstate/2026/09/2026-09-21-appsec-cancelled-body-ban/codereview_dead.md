# Dead

none

Checked non-test symbols introduced or touched in `pkg/appsec/query.go`: `errClientBodyDroppedAllow`, `isClientGoneBodyReadErr`. Grep in worktree (excluding tests/docs/openspec/knowledge/devstate): `errClientBodyDroppedAllow` — definition plus `Query` (`errors.Is`) and `newAppsecBodyRequest` (return); `isClientGoneBodyReadErr` — definition plus call from `newAppsecBodyRequest` on the `io.ReadAll` error path. Both sit on the production chain `Query` → `newAppsecForwardRequest` → `newAppsecBodyRequest`. Test-only additions (`failingBody`, `newReadablePostWithFailingBody`, assert helpers in `zzz_query_test.go`) are test sources only — out of scope for this axis.
