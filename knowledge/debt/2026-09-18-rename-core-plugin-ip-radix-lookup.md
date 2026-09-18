# Rename `core_plugin_ip_radix-lookup` to a leaf that names GetRemoteIP

IssueKey: 2026-09-18-ipv6-zone-id-trusted-hop
Size: large
Action: note

## Why this follow-up
Family `core_plugin_ip` is right. Leaf `radix-lookup` names the Checker radix, not the GetRemoteIP / parse / hop-trust contract that later folds keep adding.

## Why it was not taken
Archive history, existing cites, and usage packets already point at this id. Unattended take is only small rows on files this run created. Explore said do not rename this spec.

## Risks
Later zone / hop / insecure deltas keep folding into a leaf that hides the unit.

## Context
Current: `openspec/specs/core_plugin_ip_radix-lookup`
Proposed: a legal 4th part under `core_plugin_ip` that names GetRemoteIP / hop trust (needs approval).
