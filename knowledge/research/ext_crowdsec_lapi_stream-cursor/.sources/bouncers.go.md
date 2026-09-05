---
url: https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/database/bouncers.go
title: UpdateBouncerStreamPull and key lookup
fetched: 2026-09-05
authority: source
ref: github.com/crowdsecurity/crowdsec@e5da1b24a5dc0311ddcab74a5522b8feafbcbaee:pkg/database/bouncers.go
---

SelectBouncers(ctx, apiKeyHash, authType): all rows with that hashed key + auth type, ordered by ID ascending. Comment: manually created bouncer first, used as base name when automatically creating a new entry if API keys are shared.
SelectBouncerWithIP(ctx, apiKeyHash, clientIP): First() where APIKeyEQ and IPAddressEQ.
UpdateBouncerLastPull: UpdateOneID(id).SetLastPull only (live GET /decisions path).
UpdateBouncerStreamPull(ctx, lastPull, streamCursor, id): UpdateOneID(id).SetLastPull(lastPull).SetStreamCursor(streamCursor). No compare-and-swap, no lock.
CreateBouncer stores the (already hashed) apiKey on a new row; name must be unique.
