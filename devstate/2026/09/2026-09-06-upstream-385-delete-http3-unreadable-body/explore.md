# Explore
IssueKey: 2026-09-06-upstream-385-delete-http3-unreadable-body

## Concepts

**Unreadable body**:
`pkg/appsec/query.go` `isBodyUnreadable` is true when the request has a real `Body` (not nil / `http.NoBody`), `ProtoMajor >= 2`, and `ContentLength < 0`. That matches quic-go HTTP/3 wrapping a QUIC stream with `ContentLength = -1` when `Content-Length` is absent — including bodyless methods.

**Method-with-body drop**:
`isMethodWithBody` currently returns true for POST, PUT, PATCH, and DELETE. `newAppsecBodyRequest` drops those when the body is unreadable and `crowdsecAppsecFailureAction` is not `passthrough`, with error `appsecQuery:unreadableBody dropped`. The bouncer then `handleBanServeHTTP` (403) before origin. GET/HEAD already skip the drop (`Test_appsecQuery_unreadableBodyGetNotDropped`).

**Headers-only AppSec GET**:
When the drop does not fire, an unreadable body is forwarded to AppSec as `http.MethodGet` with no body. AppSec still sees the original method in `X-Crowdsec-Appsec-Verb`.

```
  HTTP/3 DELETE (no Content-Length)
        │
        ▼
  isBodyUnreadable = true (proto 3, ContentLength -1, wrapped body)
        │
        ├─ isMethodWithBody(DELETE) = true  ──► drop ──► 403 (today)
        └─ after fix: DELETE not in set ──► headers-only GET to AppSec ──► origin if allow
```

## Decisions

- Remove `http.MethodDelete` from `isMethodWithBody`. POST/PUT/PATCH stay; gRPC streams are POST (`Test_appsecQuery_dropUnreadableBody`).
- Add `Test_appsecQuery_unreadableBodyDeleteNotDropped` mirroring the GET HTTP/3 test.
- Fold the spec change onto `core_plugin_appsec_failure-action` (unreadable body applies to a method that would have sent a body — DELETE is no longer in that set). Do not add a new spec family.
- Usage packet `knowledge/devdocs/core_plugin_appsec.md` already names the failure-action path. Propose/devdocsimpact may add a DELETE gotcha; do not invent a second AppSec packet.
- Client IP stays `pkg/ip.GetRemoteIP` → `Query(ip, …)`. This change does not reconstruct identity.

## Open questions

- Q: Should a DELETE that intentionally carries a body over HTTP/3 still be dropped when unreadable?
  Decision: resolved — no. Treat DELETE like GET/HEAD. Implemented: DELETE removed from `isMethodWithBody`. POST/PUT/PATCH remain the drop set.
  By: implement

- Q: Fold onto which spec?
  Decision: resolved — modify `core_plugin_appsec_failure-action` only. Change `appsec-delete-unreadable-body` folds that leaf (FindSpecHost high).
  By: propose

- Q: Who already owns the client address AppSec should see?
  Decision: resolved — `pkg/ip.GetRemoteIP` in `Bouncer.ServeHTTP`; `appsec.Client.Query` already receives that `ip`. This ticket does not change identity.
  By: explore

- Q: Reproduce the claimed DELETE drop in this tree?
  Decision: resolved — throwaway HTTP/3 DELETE (`ProtoMajor=3`, `ContentLength=-1`, blocking body, `FailureActionBan`) returned `appsecQuery:unreadableBody dropped` without blocking. Throwaway file deleted after the run.
  By: explore
