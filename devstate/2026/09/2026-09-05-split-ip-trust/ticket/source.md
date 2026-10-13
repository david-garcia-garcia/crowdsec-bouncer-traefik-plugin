# Ticket

Title: Split pkg/ip hop-trust from Range CIDR

Physical isolation: pkg/ip/ip.go is two domains. Desired: hop-trust types in one file with tests; InNetwork in another file keeping existing tests. Behavior unchanged. Coverage for the path Bouncer uses every request (GetRemoteIP + trusted pool).

pkg/ip mixes hop-trust (`GetRemoteIP` / `Checker` / `PoolStrategy`) with Range CIDR (`InNetwork`). Only `InNetwork` has a unit test (`pkg/ip/ip_test.go`). Same package, split files (e.g. trust.go vs network.go). Add hop-trust unit tests next to the trust type: GetRemoteIP, Checker.Contains, X-Forwarded-For walk. Do not rename the package. Do not move InNetwork into decisionscope. Do not change bouncer call sites except import path if a file move requires none (same package).

Sibling tickets you MUST NOT take: 2026-09-05-split-connection-files, 2026-09-05-split-configuration-files, 2026-09-05-scope-headers-identity, 2026-09-05-remediation-codes-owner, 2026-09-05-decisionscope-mode-bool, 2026-09-05-config-prepare-snapshot.
