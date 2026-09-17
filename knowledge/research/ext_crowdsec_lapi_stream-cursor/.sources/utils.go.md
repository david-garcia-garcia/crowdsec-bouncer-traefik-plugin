---
url: https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/apiserver/controllers/v1/utils.go
title: getBouncerFromContext
fetched: 2026-09-05
authority: source
ref: github.com/crowdsecurity/crowdsec@e5da1b24a5dc0311ddcab74a5522b8feafbcbaee:pkg/apiserver/controllers/v1/utils.go
---

getBouncerFromContext: ctx.Get(middlewares.BouncerContextKey) as *ent.Bouncer. StreamDecision uses this snapshot (including StreamCursor and LastPull). The middleware, not this helper, chooses which row.
