# Explore
IssueKey: 2026-09-05-decisionscope-mode-bool

## Concepts

Matching (`pkg/decisionscope`) merges Ip, Range, and header-scope cache hits. Range on the request path is in-process **Range membership**, not a `range-index` blob Get. Stream and alone consult membership; live/none do not.

The Traefik plugin config bag (`pkg/configuration`) owns Crowdsec mode strings (`stream`, `alone`, `live`, `none`, `appsec`). Matching currently imports that bag only to compare `mode == StreamMode || mode == AloneMode`.

```
configuration.StreamMode / AloneMode
        │  (caller already knows)
        ▼
bouncer.ServeHTTP
        │  useRangeMembership bool
        ▼
LookupCachedRemediation(cache, useRangeMembership, remoteIP, scopes, membership)
        │
        └── pkg/decisionscope  — no configuration import
```

Usage packet `knowledge/devdocs/core_plugin_decisionscope.md` still shows a `mode` argument. Spec `core_plugin_decisions_scopes` requires stream/alone to use membership and live/none to skip the blob; it does not mention the Go import.

This work does not set or reconstruct identity. Client IP stays `pkg/ip.GetRemoteIP`.

## Decisions

- Replace the `mode string` argument with `useRangeMembership bool`. True means consult membership (today’s stream/alone branch). False skips it (today’s live/none).
- Keep `*RangeMembership`. The ticket Desired line omitted it; that argument is already the Range owner.
- ServeHTTP computes the bool from `b.conn.Mode()` vs `configuration.StreamMode` / `AloneMode`. No new connection helper (would be extra API; bouncer already imports configuration).
- Tests pass `true` / `false` instead of `"stream"` / `"none"`.
- Do not move remediation constants. Do not split connection or configuration files. Do not change identity.
- Fold spec delta onto `core_plugin_decisions_scopes`: matching MUST NOT import `pkg/configuration`; the request lookup takes a caller bool. Runtime Range behavior unchanged.
- Usage snippet update is a produce gap for implement / devdocsimpact, not a product hunk in explore.

## Open questions

- Q: What is the bool parameter named?
  Decision: assumed — `useRangeMembership` (ticket allowed equivalent of `useRangeIndex`; the request path uses membership, not the range-index blob).
  By: explore

- Q: Does ServeHTTP compute the bool inline, or does CrowdsecConnection grow a helper?
  Decision: assumed — inline at the lookup call from `Mode() == StreamMode || Mode() == AloneMode`. No new connection method.
  By: explore

- Q: Does LookupCachedRemediation drop the existing membership argument (ticket Desired omitted it)?
  Decision: resolved — keep `*RangeMembership`. This ticket only replaces the mode string.
  By: explore

- Q: Who owns client identity for this lookup?
  Decision: resolved — `pkg/ip.GetRemoteIP` already owns the address. This change does not reconstruct it.
  By: explore

- Q: New spec leaf or fold?
  Decision: assumed — fold onto existing `core_plugin_decisions_scopes`. Add that the lookup takes a bool from the caller and MUST NOT import `pkg/configuration`.
  By: explore
