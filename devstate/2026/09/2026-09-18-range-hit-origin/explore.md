# Explore
IssueKey: 2026-09-18-range-hit-origin

## Concepts

**Range index** is the shared `cidr=remediation` blob. Stream/alone rebuild in-process membership from it. The request path must not walk the blob.

**Range membership** is two `iplookup.Helper` trees (ban, captcha) plus today's `storedByCIDR` map (`cidr` → letter or letter plus U+001F origin). Ban is asked first. Nil or empty membership is a miss. `pkg/decisionscope/rangemembership.go`

**IP lookup helper** is the in-tree binary radix (`pkg/iplookup`). `radixNode` today stores `isEndpoint` and `prefixLen` only. `IsContained` returns found + longest prefix length. Trusted-IP `Checker` uses that as a boolean set and ignores prefix length. `pkg/ip/checker.go`

**storedMatchingPrefix** is the Range-hit cliff. After `IsContained` already has `prefixLen`, it walks every `storedByCIDR` key, `net.ParseCIDR` + `Contains`, and returns the first stored string whose mask `ones` equals `prefixLen` (else any containing CIDR of that kind, else the kind letter).

```
request IP
    │
    ▼
ban.IsContained ──hit──► storedMatchingPrefix (O(n) ParseCIDR)
    │ miss
    ▼
captcha.IsContained ──hit──► storedMatchingPrefix
    │ miss
    ▼
"" (Range miss, already O(prefix))
```

Client address stays `pkg/ip.GetRemoteIP`. This ticket does not reconstruct identity. Origin is the winning CIDR's stored suffix (metrics), not a host hop.

## Decisions

- Keep two trees. Ban-over-captcha is "ask ban first," not one LPM payload tree. `core_plugin_ip_radix-lookup` already forbids collapsing ban+captcha so a longer captcha cannot hide a containing ban.
- Put the stored remediation string on the winning radix endpoint of the helper that already matched. Range hit becomes the same walk `IsContained` already does.
- `AddCIDR` stays a boolean insert (empty payload). Trusted-IP `Checker` keeps calling it. Range hydrate uses a new insert that stores the blob line's remediation on that endpoint.
- `IsContained` signature stays `(bool, int, error)`. Checker must not grow a payload return. Range `Remediation` reads the stored string from the winning node of the helper that hit.
- Drop `storedByCIDR` and `storedMatchingPrefix`. Nothing else reads the map (`pkg/decisionscope` only).
- Do not change Redis, live/none hydration, or the `range-index` line format. Membership still rebuilds from the blob after apply.
- IPv4-mapped insert already remaps `ones-96` onto the v4 root. Store the payload on that same remapped endpoint so `IsContained`'s node is the owner. The archived prefixLen-vs-`ones` fallback is not needed once the node carries the string.
- Usage packet Avoid "one LPM tree with a stored remediation" still holds (two helpers). Update Language/usage so a Range helper endpoint MAY carry the stored string; Checker stays boolean. Spec `Range membership may reuse boolean CIDR prefix lookup` currently MUST NOT store a payload — that requirement changes.

## Open questions

- Q: Who already owns the client address this lookup classifies?
  Decision: resolved — `pkg/ip.GetRemoteIP` owns the client address (`req.ipAddr` / `req.remoteIP`). This change reuses that `net.IP` in `RangeMembership.Remediation`. It does not re-parse `RemoteAddr` or geolocate. Origin on the stored string is the CrowdSec metrics suffix already owned by `range-index` / `RemediationWithOrigin`.
  By: explore

- Q: Does `Helper.AddCIDR` grow an optional payload, or is a new insert path added?
  Decision: resolved — `AddCIDRRemediation(cidr, remediation)` stores the string; `ContainedRemediation` reads the longest match. `AddCIDR` / `IsContained` stay boolean.
  By: propose

- Q: Does `storedByCIDR` remain after the endpoint holds the string?
  Decision: resolved — dropped. Hydrate writes the string onto the node at insert.
  By: implement

- Q: Does a prefixLen vs stored-key `ones` mismatch (IPv4-mapped `/96` vs remapped IPv4 `0`) still need `storedMatchingPrefix`?
  Decision: resolved — no. Insert stores the remediation on the same endpoint `contains` reports. `TestHunt_MembershipIPv4MappedCIDRDoesNotPanic` still locks `::ffff:0:0/96=t` → `192.0.2.1` ban.
  By: implement

- Q: When two blob keys occupy the same remapped endpoint (`0.0.0.0/0` and `::ffff:0:0/96` on v4 `/0`), which stored string wins?
  Decision: resolved — last successful insert of that kind wins (blob order). Locked by `TestMembershipFromIndexMappedLastInsertWins`.
  By: implement

- Q: Must the range-index blob format change?
  Decision: resolved — no. Ticket forbids it unless request-path lookup would be wrong. Payload is an in-process node field rebuilt from existing `cidr=remediation` lines.
  By: explore
