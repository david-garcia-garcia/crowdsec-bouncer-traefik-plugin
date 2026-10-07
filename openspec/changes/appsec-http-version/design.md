## Context

See proposal.md — Why. Dest `newAppsecForwardRequest` (`pkg/appsec/query.go`) is the only setter of `X-Crowdsec-Appsec-*` headers. It already has `req clientrequest.Request`, which embeds the inbound `*http.Request`, so `ProtoMajor` / `ProtoMinor` are already on `req`. Official protocol: https://docs.crowdsec.net/docs/appsec/protocol (integer form `10`, `11`, …). Parse owner in CrowdSec is `applyHTTPVersion` (`github.com/crowdsecurity/crowdsec@3d5c4d9b:pkg/appsec/request.go`). Research: `knowledge/research/ext_crowdsec_appsec_protocol/`. Upstream report: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/400.

## Goals / Non-Goals

**Goals:**
- Send the client HTTP version on the existing CrowdSec header block in `newAppsecForwardRequest`.
- Encode with the same two-digit sprintf CrowdSec parses.
- Prove it in `pkg/appsec/zzz_query_test.go` via `forwardCaptureRoundTripper`.

**Non-Goals:**
- Copying upstream `appsecQuery` verbatim.
- Changing other `X-Crowdsec-Appsec-*` headers.
- Snapshotting proto on `clientrequest.New`.
- Rewriting the e2e AppSec mock unless that is the only way to prove the header (it is not).
- Teaching AppSec rules; this plugin only forwards the digits.

## Decisions

1. **Seam is `newAppsecForwardRequest`.** Add one `Header.Set` beside Ip, Uri, Host, Verb, Api-Key, and User-Agent. Alternative: set it in `appsecQuery` as upstream PR 400 does — rejected; this tree split forward construction into `newAppsecForwardRequest` and requirement Out of scope forbids a verbatim copy.

2. **Owner is inbound `req.ProtoMajor` / `req.ProtoMinor`.** `clientrequest.Request` already embeds `*http.Request`. Alternative: parse `req.Proto` — rejected; that reconstructs a fact the owner already computed. Alternative: snapshot on `clientrequest.New` — rejected; proto is not a constructor-owned cluster field like scheme or remote IP.

3. **Encoding is `fmt.Sprintf("%d%d", ProtoMajor, ProtoMinor)`.** Official docs name integer form `10`, `11`, …. CrowdSec `applyHTTPVersion` reads exactly two ASCII digits. Alternative: send `HTTP/1.1` — rejected; docs say integer form.

4. **Omit when `ProtoMajor` is 0.** `"00"` is not a real client protocol; missing header leaves AppSec on the listener connection proto (this client's AppSec transport is HTTP/1.1). Real Traefik requests have `ProtoMajor` >= 1. Alternative: always send — rejected; would apply `"00"` into `r.Proto`.

5. **HTTP/3 is `"30"`.** Same sprintf; `applyHTTPVersion` accepts any two digits (`r.Proto` becomes `HTTP/3.0`). This plugin already treats `ProtoMajor` 3 in `isBodyUnreadable`. Alternative: skip HTTP/3 because Desired named only `"10"` / `"11"` / `"20"` — rejected; that would invent a third encoding.

6. **Test in `pkg/appsec/zzz_query_test.go`.** Drive `Query` through `newForwardCaptureClient` / `forwardCaptureRoundTripper` (already records outbound headers). Table: 1.1 → `11`, 2.0 → `20`, 3.0 → `30`, `ProtoMajor` 0 → absent. Alternative: e2e mock — rejected; unit capture is the smallest proof.

## Risks / Trade-offs

- [A zero `ProtoMajor` test request omits the header] → AppSec keeps connection proto; that matches the assumed explore Decision and CrowdSec source for a missing header.
- [sprintf would emit three digits if `ProtoMinor` were >= 10] → not a real HTTP version; leave it. Do not pad or truncate.
- [Official protocol table lists the header as required; CrowdSec source treats absence as optional for old bouncers] → this plugin still sends it whenever `ProtoMajor` >= 1 so rules can see the original client protocol.

## Migration Plan

None. No Traefik config keys. Deploy picks up the header on the next Query.

## Open Questions

None — ticket decisions stand on `explore.md`.
