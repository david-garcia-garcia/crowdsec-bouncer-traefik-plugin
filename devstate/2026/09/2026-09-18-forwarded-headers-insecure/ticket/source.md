# Ticket source: bouncerForwardedInsecure

Scratch source for the ticket. Copy to `ticket/source.md` in the bus folder and delete this
file from the repo root.

Scope fence: `pkg/ip`, `pkg/configuration`, `pkg/bouncer`, `openspec/specs/core_plugin_ip_radix-lookup/`,
`knowledge/devdocs/core_plugin_ip.md`, `README.md`. Nothing else. Do not touch captcha, appsec,
cache, lapi or reclaim code.

## Problem

An operator behind a CDN cannot tell this plugin "Traefik already decided the client IP, use it".
`BouncerForwardedTrustedIPs` does two jobs at once: it gates the socket peer in `GetRemoteIP`
(`pkg/ip/checker.go:137-158`) and it skips hops inside the header value in `PoolStrategy.getIP`
(`pkg/ip/checker.go:102-127`). The two pull in opposite directions, so no value expresses
"trust any peer, take the header".

Proven by an executed scratch test (deleted afterwards):

| pool | peer | `X-Real-Ip` | result |
|------|------|-------------|--------|
| `0.0.0.0/0`, `::/0` | `203.0.113.7:443` | `198.51.100.9` | `203.0.113.7` |
| `10.0.0.0/8` | `10.1.2.3:443` | `198.51.100.9` | `198.51.100.9` |
| `10.0.0.0/8` | `203.0.113.7:443` | `198.51.100.9` | `203.0.113.7` |
| `10.0.0.0/8` | `10.1.2.3:443` | `10.9.9.9` | `10.1.2.3` |

A catch-all passes the peer gate, then classifies the header value itself as a trusted hop, so
the walk returns empty and the code falls back to `RemoteAddr` with no log. Listing private
ranges works only when the peer is private and the client is not.

Consuming `X-Real-Ip` is safe in this deployment because Traefik's entrypoint already sanitizes
it: `XForwarded.ServeHTTP` deletes every `X-Forwarded-*` header and `X-Real-Ip` when the peer is
not in the entrypoint's own `forwardedHeaders.trustedIPs`, and `rewrite` only writes `X-Real-Ip`
when it is absent, filling it with the socket peer. Verified against traefik v3.6.8,
`pkg/middlewares/forwardedheaders/forwarded_header.go:31-43,133-138,154-161`. The plugin's own
gate is therefore redundant in that topology and only forces the operator to duplicate the CDN
address list.

## Decided contract

Decisions are made. Implement them, do not re-open them.

1. New config field on `Config` (`pkg/configuration/configuration.go`), placed between
   `BouncerForwardedHeader` (line 99) and `BouncerForwardedTrustedIPs` (line 101):
   `BouncerForwardedInsecure bool` with tag `json:"bouncerForwardedInsecure,omitempty"`.
   Default `false`, set explicitly in `New()` beside the other false bools (near line 202).
   Name chosen for parity with Traefik's `forwardedHeaders.insecure` and with the existing
   `LapiTlsInsecureVerify` / `AppsecTlsInsecureVerify` opt-outs.

2. `false` keeps today's behaviour bit for bit. Every existing scenario in
   `openspec/specs/core_plugin_ip_radix-lookup/spec.md:65-91` stays true and every existing case
   in `pkg/ip/zzz_checker_test.go` keeps passing unchanged in outcome.

3. `true` changes `GetRemoteIP` only:
   - Keep the `net.SplitHostPort(req.RemoteAddr)` step first. A `RemoteAddr` that is not
     `host:port` still returns the `GetRemoteIP:extractIP` error even when the header is valid.
   - Do not call `getIP`. Do not consult `PoolStrategy.Checker`.
   - Read the whole value of `req.Header.Get(customHeader)` and trim it. Do not split on commas.
   - Absent, empty or whitespace-only value: fall back to the host from `RemoteAddr`, parsed
     when possible. Same as today's empty-header fallback.
   - Value that parses as a bare IP: return it plus its `net.IP`.
   - Anything else, including a comma-separated list, a port suffix such as `203.0.113.10:443`,
     a bracketed `[2001:db8::1]`, or garbage: return the raw trimmed string with a nil `net.IP`.
     That fail-closes downstream as `plugin:tech_trustipfail` (`pkg/bouncer/bouncer.go:159-162`),
     matching how `getIP` already treats an unparseable hop (`pkg/ip/checker.go:118-120`).
   - A non-empty `BouncerForwardedTrustedIPs` is ignored for `GetRemoteIP`, not a config error.
     It is still validated by `validateParamsIPs`, so a bad CIDR still fails startup.
     `BouncerClientTrustedIPs` is unaffected and still applies to the chosen address.

4. Effective header name when the flag is on. If `BouncerForwardedHeader` still holds the
   default `"X-Forwarded-For"`, the effective header becomes `"X-Real-Ip"`, because that is the
   header Traefik sanitizes and because `X-Forwarded-For` is a list, which would fail closed on
   every request. Resolve this in `bouncer.New` when populating `forwardedCustomHeader`
   (`pkg/bouncer/bouncer.go:71`), not inside `pkg/ip`, and emit one `log.Info` at construction
   naming the header actually in use. Any explicitly configured name other than
   `X-Forwarded-For` is honoured as written, including one whose value is a list, which then
   fail-closes per point 3.

   Note for the reviewer: an operator who deliberately writes
   `bouncerForwardedHeader: X-Forwarded-For` alongside the flag is indistinguishable from one
   who left the default, and gets `X-Real-Ip`. That is accepted, and the startup log plus the
   README make it discoverable.

5. Signature becomes
   `GetRemoteIP(req *http.Request, strategy *PoolStrategy, customHeader string, insecure bool)`.
   Do not put the flag on `PoolStrategy`; that type is the checker, and hiding "ignore the
   checker" inside it invites a future caller to reach for `getIP` anyway. Call sites to update:
   `pkg/bouncer/bouncer.go:146` and the tests.

6. No new `ValidateParams` rejection and no validate-time warning. This matches how
   `LapiTlsInsecureVerify` is treated: a dangerous but intentional setting is accepted.
   The only new log is the one from point 4.

## Spec and devdoc amendments

- `openspec/specs/core_plugin_ip_radix-lookup/spec.md:62-63` currently asserts the peer gate with
  no exception. Prefix the existing SHALL with the `BouncerForwardedInsecure` condition, keep all
  current scenarios as the default path, and add a separate requirement plus scenarios for the
  insecure path. Do not cram it into that paragraph.
- `knowledge/devdocs/core_plugin_ip.md:13-15` (the `GetRemoteIP` Language entry) needs the same
  conditional. Its Gotchas at lines 57-58 say a catch-all pool is silently ignored and that there
  is no defer-to-Traefik mode; the first stays true for the default path, the second becomes
  false and must be rewritten to point at the flag.
- Update the code comment block at `pkg/ip/checker.go:130-135` to match the new contract.
- `knowledge/research/ext_traefik_forwardedheaders_x-real-ip/notes.md:36-38` also claims there is
  no defer-to-Traefik mode. Correct it if that file exists in your tree.

## README

The docs ship with this ticket. Add the new knob to the option reference near
`BouncerForwardedHeader` and `BouncerForwardedTrustedIPs`, and add these facts, all verified,
so state them plainly:

1. The named header is only read when the socket peer is inside `BouncerForwardedTrustedIPs`, and
   a non-empty list is still checked per request.
2. That same list also skips hops inside the header value, right-to-left, first value not in the
   list wins.
3. Without the new flag there is no way to trust every peer. A catch-all `0.0.0.0/0` plus `::/0`
   passes the peer check but then treats the header value as a trusted hop and falls back to the
   connecting address with no warning. Example: pool `0.0.0.0/0` plus `::/0`, peer `203.0.113.7`,
   `X-Real-Ip: 198.51.100.9` resolves to `203.0.113.7`.
4. `0.0.0.0/0` covers IPv4 only and `::/0` covers IPv6 only, so an IPv4-only catch-all leaves an
   IPv6 peer untrusted.
5. Listing the private ranges `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` is the alternative
   to enumerating proxy addresses when Traefik sits behind a private-network ingress. It needs the
   peer to be inside a listed range and the real client not to be. Verified working: pool
   `172.16.0.0/12`, peer `172.18.0.5`, `X-Real-Ip: 198.51.100.9` resolves to `198.51.100.9`.
   Verified failure: pool `10.0.0.0/8`, peer `10.1.2.3`, `X-Real-Ip: 10.9.9.9` resolves to
   `10.1.2.3`, so internal clients inside a listed range are mis-resolved.
6. `X-Real-Ip` is trustworthy only when the proxy in front actually sets it. Traefik's entrypoint
   deletes `X-Forwarded-*` and `X-Real-Ip` from untrusted peers and only writes `X-Real-Ip` when
   absent, filling it with the socket peer. Cloudflare sends `CF-Connecting-IP` and
   `X-Forwarded-For` but not `X-Real-Ip`, so Traefik would fill in the Cloudflare edge address and
   every visitor would be remediated as Cloudflare. `X-Real-Ip` is the right choice with an nginx
   or HAProxy front end that sets it explicitly.
7. For the new flag itself, document that it skips the socket-peer gate, treats the header as a
   single client address with no hop walk, defaults the header to `X-Real-Ip`, and is safe only
   when the Traefik entrypoint in front has `forwardedHeaders.trustedIPs` set and is not running
   with `forwardedHeaders.insecure: true`. Otherwise any client can choose which IP this plugin
   bans, captchas and caches.

Match the existing option-list style: `- OptionName`, then indented `  - type`,
`  - default: ...`, then description bullets. Complete sentences, no emoji.

Do not rebase away or restructure unrelated README changes; work from master and touch only the
forwarded-headers option entries plus the new knob.

## Tests

Convention is the `zzz_` filename prefix (`openspec/specs/std_go_test_zzz-prefix/spec.md:8`).

Grow `pkg/ip/zzz_checker_test.go` (`TestGetRemoteIP`, lines 107-255) with an `insecure` column.

Flag off, must keep failing closed:
- untrusted `RemoteAddr` with a forged header returns the peer
- empty pool with a header present returns the peer
- all hops trusted returns `RemoteAddr`
- malformed hop, malformed right-most hop and port-suffixed hop return the raw string with nil parse
- `RemoteAddr` without a port errors
- new case: pool `0.0.0.0/0` plus `::/0`, peer `203.0.113.7:443`, `X-Real-Ip: 198.51.100.9`
  resolves to `203.0.113.7`. This is the proven silent catch-all and is not covered today.

Flag on:
- absent, empty and whitespace-only header, any peer, returns the `RemoteAddr` host
- `X-Real-Ip: 198.51.100.9` with an untrusted peer and an empty pool returns `198.51.100.9`
- same with a non-empty list that does not contain the peer still returns `198.51.100.9`
- same with a catch-all pool still returns `198.51.100.9`, proving the flag is not another catch-all
- `X-Forwarded-For: 203.0.113.10, 10.0.0.1` returns the whole string with nil parse
- `not-an-ip`, `203.0.113.10:443` and `[2001:db8::1]` return the raw string with nil parse
- `RemoteAddr` without a port still errors even with a valid header

Grow `pkg/configuration/zzz_configuration_test.go`: the field defaults to false; the flag plus a
populated trusted list is accepted; the flag plus an invalid CIDR still fails.

Add one `pkg/bouncer` case covering point 4: flag on with the default custom name resolves the
effective header to `X-Real-Ip`, and an explicit non-default name is passed through untouched.

## Gates before it can be proposed for merge

`go build ./...`, `go vet ./...`, `go test ./pkg/...` and `go test .` must all pass. The last one
is the Yaegi interpreter suite, roughly 50 seconds, and it is the one that really protects this
plugin. `golangci-lint run ./...` needs `C:\Program Files\Git\usr\bin` prepended to PATH on this
host, otherwise goimports aborts with a missing `diff` executable. Master currently has one
pre-existing `nestif` finding in `pkg/configuration/configuration.go`; do not fix it here and do
not let it be mistaken for a regression.

Do not merge. The repository owner approves every merge personally.
