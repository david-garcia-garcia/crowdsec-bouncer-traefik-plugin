# upstream#385 — local dump

## Upstream issue

- title: DELETE without body over HTTP/3 still blocked with 403 (crowdsecAppsecUnreadableBodyBlock) — v1.7.1
- state: CLOSED
- url: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/385
- created: 2026-08-31T11:23:33Z
- updated: 2026-09-05T08:55:02Z
- labels: (none)

### Body

Hi,

PR #352 fixed GET/HEAD over HTTP/3 by gating the "unreadable body" drop on `isMethodWithBody`. But `DELETE` is still in that list, so a bodyless DELETE over HTTP/3 gets the same 403. @dani already flagged this in [#352 (comment)](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/352#issuecomment-5047536675) on Jul 22 — the PR was merged the next day without addressing it.

I hit this in production last week. A Next.js admin panel doing `fetch(url, { method: "DELETE" })` (no body, no Content-Length) behind Traefik 3.7 + HTTP/3 + CrowdSec was silently 403-ing. Same request over HTTP/2 worked fine. No decision in `cscli decisions list`, no AppSec rule match logged — the 403 comes from the bouncer itself.

Traefik access log on HTTP/3:
```json
{
  "DownstreamStatus": 403,
  "OriginStatus": 0,
  "OriginContentSize": 0,
  "OriginDuration": 0,
  "ServiceAddr": null,
  "ServiceName": null,
  "RequestProtocol": "HTTP/3.0",
  "RequestMethod": "DELETE",
  "RequestPath": "/api/admin/reservations/8fff14a2-1095-4934-b34e-109443725242",
  "Overhead": 413912,
  "Duration": 413912
}
```
`OriginStatus: 0` + `ServiceAddr: null` → bouncer blocked before backend.

Same request over HTTP/2:
```json
{
  "DownstreamStatus": 200,
  "OriginStatus": 200,
  "ServiceAddr": "172.18.0.8:3000",
  "RequestProtocol": "HTTP/2.0",
  "RequestMethod": "DELETE"
}
```

Root cause is the same as #351: quic-go's HTTP/3 server always wraps the QUIC stream in a `requestBody` and sets `ContentLength = -1` when `Content-Length` is absent — including for bodyless DELETEs. `isBodyUnreadable` flags it (`ProtoMajor >= 2 && ContentLength < 0`), and since `DELETE` is in `isMethodWithBody`, the drop fires.

The reference `lua-cs-bouncer` also includes `DELETE` in `METHODS_WITH_BODY`, but the semantics there are "the method *can* carry a body, so if the body is unreadable, it's suspicious". For a browser-initiated `DELETE` without a body, this is a false positive — the request is intentionally bodyless. A `DELETE` without a body is valid per RFC 7231 and is the norm in REST APIs and browser `fetch()` calls.

Workaround: `crowdsecAppsecUnreadableBodyBlock: false`. Works, but it's a global hammer — it disables the drop for all methods, not just DELETE.

The fix is one line — remove `DELETE` from `isMethodWithBody`. gRPC streams are always POST, so this doesn't weaken the #323/#332 protection.

```diff
 func isMethodWithBody(method string) bool {
 	switch method {
-	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
+	case http.MethodPost, http.MethodPut, http.MethodPatch:
 		return true
 	default:
 		return false
 	}
 }
```

Environment: Traefik v3.7.12, plugin v1.7.1, CrowdSec v1.7.8, quic-go v0.59.1 (via Traefik), Chrome 151 (HTTP/3).

How you guys see it?

## Assessment

- relevant: yes
- kind: bug
- affected: yes
- status: present-unfixed
- proof: none
- recommended-action: fix
- slug: 2026-09-06-upstream-385-delete-http3-unreadable-body
- rationale: Our AppSec forward path still treats `DELETE` as a body-carrying method in `isMethodWithBody` (`pkg/appsec/query.go`), so a bodyless HTTP/3 DELETE with `ContentLength == -1` (quic-go always wraps a stream body) matches `isBodyUnreadable` and, under the default `crowdsecAppsecFailureAction: ban`, returns `appsecQuery:unreadableBody dropped`; the bouncer then bans with 403 before origin (`pkg/bouncer/bouncer.go`). Issue #351 fixed the same false positive for GET/HEAD but not DELETE. Workaround is `crowdsecAppsecFailureAction: passthrough`, which disables the drop for all methods.

### Evidence
- current: pkg/appsec/query.go
- tests: pkg/appsec/query_test.go (Test_appsecQuery_unreadableBodyGetNotDropped covers GET only; no DELETE case)
