# Explore

## Concepts

```
LAPI Range value (bare IP or CIDR)
        │
        ▼
ApplyRangeBatch  ── upserts any non-empty trim ──►  range-index  "192.0.2.1=t"
        │
        ▼
MembershipFromIndex
        │  helper.AddCIDR(network)  ==  net.ParseCIDR only
        │  bare IP → error → skip
        ▼
RangeMembership.Remediation(client net.IP)  →  ""
```

**Range index** is the shared `cidr=remediation` blob. **Range membership** rebuilds two `iplookup.Helper` trees from that blob. `AddCIDR` is ParseCIDR-only (`pkg/iplookup/iplookup.go`). Trusted-pool **hostCIDR** already maps a parseable bare IP to `/32` or `/128` before `AddCIDR` (`pkg/ip/checker.go`). That mapping is unexported; reuse the rule, not a second owner.

Client address is not this ticket. `pkg/ip.GetRemoteIP` remains the owner of the request IP. The Range host is `decision.Value` from LAPI/stream.

CrowdSec persist already accepts a bare IP or a CIDR on Ip/Range via `csnet.NewRange` (`knowledge/research/ext_crowdsec_decisions_scopes/notes.md`). Official Range examples are CIDR; LAPI can still store a host.

## Decisions

- Reproduced on dest checkout: `AddRange("192.0.2.1", ban)` writes blob `192.0.2.1=t`; `MembershipFromIndex.Remediation(192.0.2.1)` is `""`. Throwaway `TestThrowaway_RangeBareIPIsHostPrefix` (deleted after the run). Hunt name `TestHunt_RangeBareIPIsHostPrefix` is not on dest.
- `storedMatchingPrefix` also needs a ParseCIDR-able key. Expanding only at `AddCIDR` and leaving `storedByCIDR["192.0.2.1"]` would remediates via the tree then drop the origin suffix (fallback to the letter).
- Existing `TestMembershipFromIndexSkipsInvalidCIDR` is garbage (`not-a-cidr`), not a host. Keep skipping unparseable values.
- No new research write. The CrowdSec value-encoding note already answers persist.
- No Language write. `core_plugin_decisionscope.md` is enough to call the package; a host-prefix gotcha is a later usage gap if the apply lands without it.
- Bound: no trusted-pool behavior change, no equivalent-CIDR canonicalization, no live/`?ip=` work, no stream `range:` key rewrite.

## Open questions

- Q: Who already owns the client address this change would set?
  Decision: resolved — `pkg/ip.GetRemoteIP` owns the client address. This defect does not reconstruct it. The Range host is LAPI `decision.Value`. The `/32`/`/128` mapping is the trusted-pool `hostCIDR` rule; reuse that output, do not invent a second formatter.
  By: explore

- Q: Rewrite the blob to `/32` or `/128` on upsert, or only treat a bare IP as a host prefix at membership?
  Decision: resolved — canonicalize a parseable bare IP to `/32` or `/128` at `ApplyRangeBatch` upsert and remove so write and delete pair. Do not call `rangeIndexCIDR` in `MembershipFromIndex` (ParseCIDR-only; a leftover `192.0.2.1=t` line is skipped). Do not dual-remove the original spelling. Do not canonicalize equivalent CIDRs (`10.1.2.0/8` vs `10.0.0.0/8`).
  By: implement

- Q: Must dest add an explicit host-prefix scenario on the Range spec, or only a regression test?
  Decision: assumed — both. Add one scenario on `core_plugin_decisions_scopes` (a parseable Range host remediates that address as `/32` or `/128`) plus a regression test. Dest already says treat Range `value` as a CIDR; the scenario names the host-prefix case. Garbage values stay skipped.
  By: explore

- Q: Export `hostCIDR`, duplicate the four lines, or teach `iplookup.AddCIDR` to accept a bare IP?
  Decision: assumed — export the existing `pkg/ip` mapping (same `To4` → `/32`, else `/128`) and call it from `decisionscope`. Do not change `NewChecker`. Do not widen `Helper.AddCIDR` (CIDR-only contract stays). Unexported `hostCIDR` cannot be called from `decisionscope`.
  By: explore

- Q: Does stream `rememberActiveDecision("range:"+cidr)` need the rewritten spelling?
  Decision: assumed — no. Leave stream keys as trimmed `decision.Value`. Index and membership own the host prefix.
  By: explore
