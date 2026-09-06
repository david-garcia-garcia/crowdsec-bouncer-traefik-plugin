# Explore
IssueKey: 2026-09-06-ip-xff-trust-gate

## Concepts
- **Trusted-hop pool** — `ForwardedHeadersTrustedIPs` compiled into `serverPoolStrategy.Checker` in `bouncer.New`. Used today only to skip hops during the header walk, not to gate whether headers may be read at all.
- **RemoteAddr gate** — Before walking forwarded headers, `GetRemoteIP` must verify the socket peer host is in the trusted-hop pool. Empty pool means trust no forwarded hops (RemoteAddr only).
- **Fail-closed unparseable hop** — When a hop cannot be parsed, `getIP` returns `(raw, nil)`; bouncer remediates as `plugin:tech_trustipfail`. Product policy unchanged; add tests only.

## Decisions
- Reproduce confirmed: untrusted `RemoteAddr` `198.51.100.5:443` with header `203.0.113.10, 10.0.0.1` returns `203.0.113.10` (spoof succeeds). Empty pool with header `203.0.113.10` returns `203.0.113.10` instead of `198.51.100.5`.
- Implement the gate inside `GetRemoteIP` in `pkg/ip/checker.go` using the same `PoolStrategy.Checker` already wired from config — no second pool, no bouncer changes.
- Gate algorithm: extract host from `RemoteAddr`; if checker is nil, empty trusted list, or peer not in pool → skip header walk and return RemoteAddr host; else walk headers as today.
- Update existing `TestGetRemoteIP` cases that assume header walk without a trusted `RemoteAddr` — set `RemoteAddr` to a trusted proxy (e.g. `10.0.0.1:443`) for legitimate-chain scenarios.
- Add test cases for spoofing, empty pool + header, malformed hops, port-suffixed hop per requirement.
- Spec delta folds into `core_plugin_ip_radix-lookup` — add RemoteAddr gate requirement and scenarios; adjust existing scenario that omits trusted RemoteAddr.

## Open questions
- Q: Does the RemoteAddr trusted-proxy check reuse the same Checker as hop-skipping or need a separate pool?
  Decision: assumed — reuse `PoolStrategy.Checker` (same `ForwardedHeadersTrustedIPs` list); bouncer already passes one `serverPoolStrategy`.
  By: explore

- Q: Who owns the client address fact on the request path?
  Decision: resolved — `GetRemoteIP` remains the sole owner; bouncer consumes its string and `net.IP` only.
  By: explore

- Q: Should empty trusted pool still walk headers when RemoteAddr is loopback or missing?
  Decision: assumed — empty pool always ignores headers regardless of RemoteAddr; use RemoteAddr host only (fail closed on forwarded data).
  By: explore
