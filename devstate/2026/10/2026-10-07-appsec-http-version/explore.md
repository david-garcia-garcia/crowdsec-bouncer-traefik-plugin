# Explore

## Concepts

AppSec is an out-of-band HTTP oracle. `pkg/bouncer` calls `appsec.Client.Query` once per request (`pkg/bouncer/bouncer.go`, 1 production call site). `Query` builds the listener request in `newAppsecForwardRequest` (`pkg/appsec/query.go`). That function is the only setter of `X-Crowdsec-Appsec-*` headers (roots searched: `pkg/appsec` `Header.Set` / `crowdsecAppsec*` constants, `pkg/bouncer` for a second setter — none).

```
inbound *http.Request
  ProtoMajor / ProtoMinor   ← owner of the client HTTP version
        │
        ▼
clientrequest.Request (embeds *http.Request)
        │
        ▼
appsec.Client.Query
  newAppsecForwardRequest   ← sets Ip, Uri, Host, Verb, Api-Key, User-Agent
        │                     does not set Http-Version today
        ▼
CrowdSec AppSec
  applyHTTPVersion          ← two ASCII digits → r.Proto
```

The client HTTP version is a property of the incoming request (`net/http` `ProtoMajor` / `ProtoMinor`). This plugin does not invent it. `clientrequest.Request` already embeds that `*http.Request`.

Reproduce: **absent**. `pkg/appsec/query.go` constants list six CrowdSec headers and no `X-Crowdsec-Appsec-Http-Version`. `newAppsecForwardRequest` sets those six plus plugin `User-Agent` and never reads `ProtoMinor` for the outbound request (`ProtoMajor` is used only in `isBodyUnreadable`). Focused probe `Test_explore_appsecQuery_omitsHTTPVersion` (HTTP/1.1 and HTTP/2 via `forwardCaptureRoundTripper`) passed because the outbound header was empty; the probe file was deleted and is not the product fix. Existing `pkg/appsec/zzz_query_test.go` does not assert this header.

Outside facts: `knowledge/research/ext_crowdsec_appsec_protocol/` (updated this phase). Official protocol page https://docs.crowdsec.net/docs/appsec/protocol quoted line: "The HTTP version used by the original HTTP request (in integer form `10`, `11`, ...)". Upstream PR https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/400 quoted line: "CrowdSec AppSec expects the original request HTTP version in `X-Crowdsec-Appsec-Http-Version` as a two-digit integer string (`"10"`, `"11"`, `"20"`) to populate `r.Proto` during evaluation." Official docs do not disagree; they are thinner (ellipsis, no `ProtoMajor` / `r.Proto`). CrowdSec source `github.com/crowdsecurity/crowdsec@3d5c4d9b:pkg/appsec/request.go` `applyHTTPVersion` fills the two-digit encoding and `r.Proto`. Decision follows the docs' integer form; source is how this CrowdSec version parses it.

Usage packet `knowledge/devdocs/core_plugin_appsec.md` is enough to call `Query` today. Implement updates that How-to-use list when it adds the header. No new Language term.

## Decisions

- Seam: set `X-Crowdsec-Appsec-Http-Version` in `newAppsecForwardRequest` beside the other CrowdSec headers. Do not copy upstream `appsecQuery` verbatim (requirement Out of scope).
- Encoding: two ASCII digits, major then minor (`fmt.Sprintf("%d%d", ProtoMajor, ProtoMinor)` → `"10"`, `"11"`, `"20"`). Header name `X-Crowdsec-Appsec-Http-Version`.
- Owner: inbound `*http.Request` `ProtoMajor` / `ProtoMinor`. Reuse `req.ProtoMajor` and `req.ProtoMinor`. Do not snapshot a parallel field on `clientrequest.New`.
- Live contract: `openspec/specs/core_plugin_appsec_client/` — propose adds a Query header requirement there. No new spec folder.
- Rejected: inventing `HTTP/1.1` as the header value (docs say integer form `10`, `11`, …). Rejected: reconstructing proto from `req.Proto` string parsing when `ProtoMajor` / `ProtoMinor` are already the owner.

## Open questions

- Q: What is the official AppSec header name and value encoding?
  Rank: additive asked — new header this change sends; Desired "Confirm the header name and value encoding against official CrowdSec AppSec documentation"
  Decision: resolved — name `X-Crowdsec-Appsec-Http-Version`; value integer form `10`, `11`, … as two ASCII digits major then minor (`"10"`, `"11"`, `"20"`). Official: https://docs.crowdsec.net/docs/appsec/protocol quoted "The HTTP version used by the original HTTP request (in integer form `10`, `11`, ...)". Source `applyHTTPVersion` at `github.com/crowdsecurity/crowdsec@3d5c4d9b:pkg/appsec/request.go` quoted "parses the 2-character HTTP version header (e.g. \"11\" for HTTP/1.1, \"20\" for HTTP/2)" and updates `r.Proto`. Docs do not disagree with upstream PR 400.
  By: explore

- Q: Who already owns the client HTTP version?
  Rank: additive asked — reuse inbound proto fields already on `req`; Desired "set `X-Crowdsec-Appsec-Http-Version` from the client request protocol version"
  Decision: resolved — the incoming `*http.Request` (`net/http` `ProtoMajor` / `ProtoMinor`). `clientrequest.Request` embeds that request. This plugin does not invent the version. Read `req.ProtoMajor` and `req.ProtoMinor` in `newAppsecForwardRequest`. Do not add a constructor snapshot.
  By: explore

- Q: Where does this tree set outbound AppSec CrowdSec headers?
  Rank: additive asked — one new `Header.Set` on existing `newAppsecForwardRequest` (1 setter; roots `pkg/appsec` `Header.Set` / `crowdsecAppsec*`, `pkg/bouncer` Query — 1 production caller); Desired "If the fork is affected, set `X-Crowdsec-Appsec-Http-Version`"; Out of scope "Copying the upstream patch verbatim when this tree's `appsecQuery` shape differs"
  Decision: resolved — `newAppsecForwardRequest` in `pkg/appsec/query.go`. The fork is affected (header absent). Implement there; add the unit test in `pkg/appsec/zzz_query_test.go`.
  By: explore

- Q: Does a missing header make AppSec default to the bouncer connection version?
  Rank: additive asked — sourced default, no code reshape; Unknowns "Whether a missing header makes AppSec default to the bouncer connection version (upstream claim; not measured here)"
  Decision: resolved — yes for this CrowdSec version. Official protocol page does not state the default. Source: missing header logs debug and skips `applyHTTPVersion`, so `r.Proto` stays the AppSec listener connection proto (this plugin's AppSec client is HTTP/1.1). Official lists the header as required; source treats absence as optional for old bouncers. Follow source for AppSec behavior; this plugin still sends the header so rules can see the original client protocol.
  By: explore

- Q: Should Query omit the header when `ProtoMajor` is 0 (upstream PR 400 guard)?
  Rank: additive incidental — optional skip on `ProtoMajor` 0; requirement does not name the upstream `if httpReq.ProtoMajor > 0` guard
  Decision: assumed — omit when `ProtoMajor` is 0 so AppSec keeps connection proto instead of applying `"00"`. Real Traefik requests have `ProtoMajor` >= 1.
  By: propose

- Q: How is HTTP/3 (`ProtoMajor` 3) encoded?
  Rank: additive incidental — same two-digit encoding for `ProtoMajor` 3; Desired names `"10"` / `"11"` / `"20"` only
  Decision: assumed — `fmt.Sprintf("%d%d", ProtoMajor, ProtoMinor)` so HTTP/3 is `"30"`. `applyHTTPVersion` accepts any two digits (`r.Proto` becomes `HTTP/3.0`). This plugin already inspects `ProtoMajor` >= 2 including 3 in `isBodyUnreadable`.
  By: propose
