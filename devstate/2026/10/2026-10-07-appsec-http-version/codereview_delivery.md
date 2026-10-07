# Delivery

## Motivation

AppSec Query already stamps the required extras on the outbound listener request: client IP, URI, host, verb, API key, and User-Agent. CrowdSec AppSec also expects the original client HTTP version on `X-Crowdsec-Appsec-Http-Version` as two ASCII digits (`10` for HTTP/1.0, `11` for HTTP/1.1, `20` for HTTP/2) so it can populate `r.Proto` for rule evaluation. Upstream reported the same gap: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/400

That header is never sent. AppSec then skips `applyHTTPVersion` and keeps the listener connection proto, which is HTTP/1.1. An HTTP/2 or HTTP/1.0 client is therefore evaluated as HTTP/1.1.

Left alone, proto-aware AppSec rules cannot see the real client protocol behind the HTTP/1.1 forward. Blast radius is those rules only; CrowdSec treats a missing header as optional for old bouncers.

Priority: P2 — real operator, admin-user, or end-user pain, with a workaround or limited blast radius

## Implementation

`newAppsecForwardRequest` already holds the inbound request, so `ProtoMajor` and `ProtoMinor` are already on `req`. When `ProtoMajor` is greater than 0, it sets `X-Crowdsec-Appsec-Http-Version` to two ASCII digits, major then minor (`fmt.Sprintf("%d%d", ProtoMajor, ProtoMinor)`). HTTP/1.0 is `10`, HTTP/1.1 is `11`, HTTP/2 is `20`, HTTP/3 is `30`. When `ProtoMajor` is 0 the header is omitted so AppSec keeps the listener proto instead of applying `00`. The digits are read from those fields; `Request.Proto` is not parsed. A Query forward-capture test proves the encodings and the omit.

## What this changes
**Operators.** None.
**Admin users.** None.
**Developers.** None.
**End users.** None.