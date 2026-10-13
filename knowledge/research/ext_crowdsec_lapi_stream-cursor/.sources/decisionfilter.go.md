---
url: https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/database/decisionfilter.go
title: applyDecisionFilter id_gt
fetched: 2026-09-05
authority: source
ref: github.com/crowdsecurity/crowdsec@e5da1b24a5dc0311ddcab74a5522b8feafbcbaee:pkg/database/decisionfilter.go
---

Filter key "id_gt": parse int, query.Where(decision.IDGT(id)). This is how writeDecisions applies the bouncer stream cursor to the active-decision query. "limit" sets query.Limit. id_gt is not a public swagger argument; the controller injects it.
