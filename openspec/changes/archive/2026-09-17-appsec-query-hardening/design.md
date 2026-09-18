## Context

See `proposal.md` Why. Dest `master` already has #64 `atomic.Value` transport (`currentTransport()` / `transport.Store`). `Query` returns on 502/503/504 before `defer drainResponse`. `appsecBodyLimit > 0 && Body != nil` is the only body-copy gate; `0` falls through to GET. `readCappedAppsecBody` io errors return `nil, err`. Client headers are `Add`ed after the body is chosen; `Content-Length` is not rebuilt. `isMethodWithBody` is POST, PUT, PATCH, DELETE. Yaegi v0.16 cannot take `atomic.Pointer[T]` as a struct field consumed from another package. Client IP is already chosen before Query (`pkg/ip.GetRemoteIP` → `clientRequest.remoteIP`).

FindSpecHost:

```
verdicts:
  - { deltaId: drain-reverse-proxy-response, fold|new: fold, spec-id: core_plugin_appsec_client, confidence: high, candidates: [core_plugin_appsec_client, core_plugin_appsec_failure-action] }
  - { deltaId: unlimited-body-limit-zero, fold|new: fold, spec-id: core_plugin_appsec_client, confidence: high, candidates: [core_plugin_appsec_client] }
  - { deltaId: rebuild-outbound-content-length, fold|new: fold, spec-id: core_plugin_appsec_client, confidence: high, candidates: [core_plugin_appsec_client] }
  - { deltaId: read-body-io-through-failure-action, fold|new: fold, spec-id: core_plugin_appsec_failure-action, confidence: high, candidates: [core_plugin_appsec_failure-action, core_plugin_appsec_client] }
  - { deltaId: delete-out-of-unreadable-body-set, fold|new: fold, spec-id: core_plugin_appsec_failure-action, confidence: high, candidates: [core_plugin_appsec_failure-action] }
```

No new leaf. Do not fold into `core_plugin_appsec_bot-detection` (challenge JSON, not Query hygiene).

## Goals / Non-Goals

**Goals:**
- Drain every non-nil `Do` response, including 502/503/504.
- `crowdsecAppsecBodyLimit == 0` forwards the full readable body.
- AppSec response-body io errors use `FailureAction`.
- Outbound length matches the forwarded bytes.
- DELETE is not an unreadable-body drop.

**Non-Goals:**
- New public knobs or restoring `crowdsecAppsecUnreadableBodyBlock`.
- Gating the readable-body copy on `isMethodWithBody` (still a non-goal: the gate added in the amendment uses a separate predicate and leaves the drop set alone).
- ~~A hop-by-hop header filter (Connection, Upgrade, …).~~ — became a goal in the amendment (see Decision 9).
- Sending oversized AppSec bodies through `FailureAction`.
- gRPC / streaming body policy (#51).
- Restoring `httpClient` / `appsecKey` or using `atomic.Pointer[T]`.
- Reconstructing client IP (`Query` reuses the `ip` argument).
- Updating usage Language in this change folder (implement / devdocsimpact).

## Decisions

1. **Drain before every return that has a response.** Move drain so 502/503/504 close the body (`std_go_net-http_keep-alive-drain`). Transport `err != nil` typically has no body; do not invent one.
2. **Unlimited `0` skips `LimitReader`.** `N <= 0` is immediate EOF (`std_go_io_limit-reader`). `io.ReadAll` the client body when `appsecBodyLimit == 0`; restore for origin. No invented max cap. No new knob.
3. **Read-body io errors keep `appsecQuery:readBody`.** Call `resultForFailureAction(pol.FailureAction, err.Error())`. Log `appsecQuery:failure` like 500. Oversized 200 allow / oversized non-200 error stay as dest.
4. **Rebuild length from forwarded bytes.** Omit client `Content-Length` and `Transfer-Encoding` from `Add`; set `Request.ContentLength` and the header from those bytes (`std_go_net-http_request-content-length`). Do not add a general hop-by-hop filter.
5. **DELETE leaves `isMethodWithBody`.** Only the unreadable-body drop gate changes. Readable DELETE/GET still copy when `Body != nil` (including limit `0`).
6. **Identity stays on the `ip` argument.** `pkg/ip.GetRemoteIP` already chose it. Do not read `RemoteAddr` or Host in Query.
7. **Keep #64 transport.** Tests store into `transport`, not a restored `httpClient` field. No `atomic.Pointer[T]`.
8. **Fold two leaves.** Client: drain, zero limit, Content-Length. Failure-action: read io errors; unreadable methods POST/PUT/PATCH.

### Amendment — folded from #35 (owner closed #35 as superseded by this PR)

9. **Strip hop-by-hop headers on the forward path.** `isHopByHopHeader` covers RFC 7230 section 6.1 with errata 4522 (`Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`), matched case-insensitively. It replaces the literal `Transfer-Encoding` skip from Decision 4 rather than duplicating it; the client `Content-Length` skip stays alongside it because `Content-Length` is end-to-end, not hop-by-hop. The dynamic RFC 7230 rule (also drop names listed in the request's own `Connection` header) is **deliberately not implemented**: unlike a reverse proxy, this forward is an inspection copy, so honouring client-supplied connection-options would hand a client a lever to hide `Cookie` or any other header from the WAF. #35 did not implement it either.
10. **Two predicates, not one.** `isMethodWithBody` (POST, PUT, PATCH) keeps its single job: deciding whether an *unreadable* body is a drop candidate. The new `isMethodWithForwardableBody` (POST, PUT, PATCH, DELETE) decides whether a *readable* body is copied to AppSec. Merging them would either resurrect the DELETE drop that #43 closure ratified, or blind AppSec to DELETE payloads. The readable branch also skips `http.NoBody`, which would otherwise POST zero bytes.
11. **`Content-Length` stays on the POST branch.** #35 set it whenever `req.ContentLength >= 0`, which also stamps `Content-Length: 0` onto the bodyless GET. After Decision 10 the outbound method is POST if and only if bytes are forwarded, so the POST-only condition from Decision 4 is already exactly "set the length when we send bytes" and is the non-contradictory choice. Go's transport derives the wire length from `Request.ContentLength` regardless; the explicit header is the value AppSec reads.

## Risks / Trade-offs

- [Unlimited `0` can buffer a large body] → Operator opt-in on the existing key; default stays 10 MiB. No invented cap.
- [Yaegi rejects `atomic.Pointer[T]`] → Keep `atomic.Value` and type-assert on load.
- [Sister PRs #35 / #43 conflict on dest] → Re-implement on current `query.go`; do not rebase.
- [~~Readable-body copy stays `Body != nil`~~] → Amended: the copy is gated on `isMethodWithForwardableBody`. A readable DELETE still forwards; the unreadable drop set is unchanged.
- [Method gate hides a body from AppSec on exotic verbs] → Only POST/PUT/PATCH/DELETE bodies are inspected. A body on GET/HEAD/OPTIONS or a custom verb has no defined semantics and its presence still reaches AppSec through the headers and `X-Crowdsec-Appsec-Verb`. Accepted to stop a GET being laundered into a POST at the listener.

## Migration Plan

No operator JSON/YAML key change. `0` on the existing body-limit key becomes unlimited (dest today skips the body). Operators who omitted the key keep the 10 MiB default. Rollback is revert.
