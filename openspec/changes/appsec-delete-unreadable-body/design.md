## Context

`pkg/appsec/query.go` `isBodyUnreadable` already matches quic-go HTTP/3 (`ProtoMajor >= 2`, `ContentLength < 0`, real body). GET/HEAD skip the drop because they are not in `isMethodWithBody`. DELETE is still in that set, so a bodyless HTTP/3 DELETE under default `ban` returns `appsecQuery:unreadableBody dropped` and the bouncer 403s before origin. Explore reproduced that error with a throwaway DELETE HTTP/3 Query.

## Goals / Non-Goals

**Goals:**
- Treat DELETE like GET/HEAD for the unreadable-body drop.
- Keep POST/PUT/PATCH (and therefore gRPC POST streams) fail-closed under `ban`.
- Prove it with a DELETE unit test next to the GET case.

**Non-Goals:**
- Changing `crowdsecAppsecFailureAction` keys, defaults, or passthrough semantics.
- Distinguishing a DELETE that intended to carry a body over HTTP/3 (quic-go cannot).
- Per-method unreadable-body toggles.
- Reconstructing client IP (`pkg/ip.GetRemoteIP` remains the owner).

## Decisions

1. **Remove `http.MethodDelete` from `isMethodWithBody`.** One-line cause fix. Alternative: special-case DELETE only in `newAppsecBodyRequest` — rejected; the method set is the owner of “would have sent a body.”

2. **Do not read the DELETE body when it looks unreadable.** Headers-only GET to AppSec, same as GET. Alternative: try to buffer DELETE with a short timeout — rejected; that reintroduces the #323 stream hang class.

3. **Fold onto `core_plugin_appsec_failure-action`.** The requirement already names unreadable body on methods that would send a body. Narrow that set. Alternative: new leaf `core_plugin_appsec_delete-body` — rejected; small adjustment, not a new capability.

## Risks / Trade-offs

- [DELETE with a real unreadable stream body is no longer dropped] → accepted; HTTP/3 cannot tell that apart from a bodyless DELETE. POST/PUT/PATCH remain the drop set.
- [lua-cs-bouncer still lists DELETE in METHODS_WITH_BODY] → accepted; that “can carry a body ⇒ suspicious if unreadable” rule is a false positive for browser DELETE.

## Migration Plan

None. Default ban stays fail-closed for POST/PUT/PATCH and AppSec 500/unreachable. Rollback restores DELETE in the method set.
