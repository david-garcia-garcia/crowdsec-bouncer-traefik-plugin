---
url: https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/apiserver/middlewares/v1/api_key.go
title: API-key middleware bouncer row selection
fetched: 2026-09-05
authority: source
ref: github.com/crowdsecurity/crowdsec@e5da1b24a5dc0311ddcab74a5522b8feafbcbaee:pkg/apiserver/middlewares/v1/api_key.go
---

X-Api-Key hashed with SHA-512 hex; lookup uses the hash.
authPlain HEAD: SelectBouncers, return bouncers[0] (no IP match, no last_pull update).
Otherwise: SelectBouncerWithIP(hash, ClientIP()). Hit → that row.
Miss: SelectBouncers. If len==1 and IPAddress=="" → reuse that row (first request). Else create auto_created row named base@clientIP with the same hashed key. Comment on baseBouncerName: when a bouncer changes IP it is detected as a new bouncer, to allow for key sharing.
Middleware: if IPAddress=="" then UpdateBouncerIP. Sets gin BouncerContextKey to the chosen *ent.Bouncer.
TLS path uses a different name (CN@IP) and is not the API-key sharing path.
