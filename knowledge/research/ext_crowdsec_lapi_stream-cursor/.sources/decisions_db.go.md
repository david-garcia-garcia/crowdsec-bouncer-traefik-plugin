---
url: https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/database/decisions.go
title: Stream decision queries
fetched: 2026-09-05
authority: source
ref: github.com/crowdsecurity/crowdsec@e5da1b24a5dc0311ddcab74a5522b8feafbcbaee:pkg/database/decisions.go
---

QueryAllDecisionsWithFilters: until > now, optional longest-decision dedup, applyDecisionFilter (including id_gt / limit), order by id asc. This is the stream "new" query.
LatestDecisionID: max decision id, or 0 if none.
QueryExpiredDecisionsWithFilters: until < now (startup deleted set).
QueryExpiredDecisionsSinceWithFilters: until < now, and if since != nil also until > *since. Non-startup deleted window.
