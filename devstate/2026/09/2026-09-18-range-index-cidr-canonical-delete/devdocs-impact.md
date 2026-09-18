# Devdocs impact
change: range-index-canonical-ipnet

## Units
- Decision scopes — subsystem — `pkg/decisionscope/` / `core_plugin_decisions_scopes`
- Canonical network — pattern — Range-index write identity (`net.ParseCIDR` masked IP plus prefix ones/bits)

## Findings
- [x] stale-usage  Decision scopes — `core_plugin_decisionscope.md` gotcha names write identity and persist `String()`, but not that `String()` can collide for IPv4 vs IPv4-mapped or that unrelated leftover spellings stay
- [ ] language-gap  Canonical network — `core_plugin_decisionscope` has How-to/gotcha, no Language term
  Why: skipped — term is fuzzy (canonical network / Range-index write identity / `indexNetworkID`); do not invent a term
