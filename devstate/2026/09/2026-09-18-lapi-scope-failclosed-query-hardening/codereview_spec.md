# Spec

none.

Walked all four `### Requirement` headings in `openspec/changes/lapi-scope-failclosed-query-hardening/specs/**/spec.md` against the pinned diff.

`core_plugin_lapi_failure-action` — MODIFIED "Live LAPI error uses BouncerLapiFailureAction": every scope query counts as the lookup (`pkg/lapi/client_live.go:33-46`); a scope error is reported with a non-active remediation (`:44` returns `("", scopeErr)`); no negative live-cache write on that path (the `cacheClient.Set(remoteIP, NoBannedValue, ...)` at `:48` is now below the `scopeErr` return); logged at `WARN`, not `DEBUG` (`pkg/lapi/client_decisions.go:139`). The caller side already routes non-active + error into `applyLapiFailureAction` (`pkg/bouncer/bouncer.go:233-239`), unchanged by this diff, so `passthrough` / `ban` / `captcha` all reach the new path.

`core_plugin_lapi_failure-action` — ADDED "An active remediation outranks a header-scope failure": `IsActiveRemediation(chosen)` is tested before `scopeErr` (`pkg/lapi/client_live.go:38-43`) and still returns the existing `handleNoStreamCache:banned` signal, so the caller separates the two meanings by remediation kind alone.

`core_plugin_lapi_stream-lease` — ADDED "A failed poll releases the stream lease": `pkg/lapi/client_stream.go:90-93` deletes `cacheTimeoutKey` on any error from the extracted fetch+apply, which covers GET, decode, and apply. `Acquire`, the TTL floor, and the loser branch are untouched in the diff. Success keeps the lease (no delete on the success arm at `:95-97`).

`core_plugin_lapi_query-round-trip` — ADDED, three requirements: replay of the same method and body (`pkg/lapi/client_http.go:241` passes `data`, and `sendQuery` rebuilds the request from `data`, so a POST stays a POST); replay may not renew again (`false` at `:241`); login may not renew (`false` at `:172`); every answered response drained and closed before return (`defer c.drainResponse(res)` at `:233`, above the reverse-proxy branch); transport error wraps its cause (`:230`) and the reverse-proxy status names the code without `%w` (`:235`). The spec's "a `nil` response guard MUST NOT be added" is honoured: `:234` has no nil check.

No extra: the diff adds no config key, no outbound host, and no public surface. `sendQuery`, `drainResponse`, and `fetchAndApplyStreamDecisions` are unexported and each exists to make one SHALL true. `tasks.md` has no open box.