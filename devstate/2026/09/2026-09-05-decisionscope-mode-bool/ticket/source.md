# decisionscope mode bool

Layering: decisionscope (matching) depends on configuration (Traefik DTO) only for mode constants. Desired: LookupCachedRemediation(cache, useRangeIndex bool, remoteIP, scopes). Callers that know the mode pass true for stream/alone. pkg/decisionscope/go imports no longer include configuration.

Bound: `pkg/decisionscope` imports `pkg/configuration` only for mode strings (`StreamMode` / `AloneMode`) so `LookupCachedRemediation` can decide whether to use the range index. It already branches on “use range index”. Change the API to take a `bool` (or equivalent) instead of a mode string, and drop the configuration import from decisionscope. Update call sites (bouncer ServeHTTP, tests). Matching domain must not know the Traefik config bag.

Do not move remediation constants (sibling). Do not split files in connection.go or configuration.go. Do not change identity.

Sibling tickets not taken: 2026-09-05-split-connection-files, 2026-09-05-split-configuration-files, 2026-09-05-split-ip-trust, 2026-09-05-scope-headers-identity, 2026-09-05-remediation-codes-owner, 2026-09-05-config-prepare-snapshot.
