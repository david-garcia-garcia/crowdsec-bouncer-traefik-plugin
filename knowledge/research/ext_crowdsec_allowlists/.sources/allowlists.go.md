---
url: https://github.com/crowdsecurity/crowdsec/blob/e20782bb3c532f0b9b9a469c0bdaa003588ec8e5/pkg/database/allowlists.go
title: crowdsec database allowlists
fetched: 2026-11-14
authority: source
ref: github.com/crowdsecurity/crowdsec@e20782bb3c532f0b9b9a469c0bdaa003588ec8e5:pkg/database/allowlists.go
---

L404 ApplyAllowlistsToExistingDecisions; L405 comment "Soft delete (set expiration to now) all decisions that matches any allowlist".
Loads non-expired allowlist items (expires_at >= now or nil), splits IPv4/IPv6.
applyAllowlistBatch (L461-): per item, decision contained in the allowlist range (or exact) OR decision contains the allowlist range.
L529-536: Decision.Update().SetUntil(now).Where(decision.UntilGTE(now), decision.IPSizeEQ(ipSize), decision.Or(conditions...)). No filter on decision type.
