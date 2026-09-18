---
url: https://github.com/crowdsecurity/crowdsec/blob/a8dbeb94efb61c417b556b5468a7695a9410cb2f/pkg/database/decisions.go
title: LAPI stream new vs expired queries
fetched: 2026-09-18
authority: source
ref: github.com/crowdsecurity/crowdsec@a8dbeb94efb61c417b556b5468a7695a9410cb2f:pkg/database/decisions.go
---

QueryAllDecisionsWithFilters (stream new): until > now. Optional longestDecisionForScopeTypeValue unless filter dedup=false. applyDecisionFilter (including id_gt). Order by id asc.
QueryExpiredDecisionsWithFilters (startup deleted): until < now. Same optional longest-decision dedup. Order by id asc.
QueryExpiredDecisionsSinceWithFilters (delta deleted): until < now, and if since != nil also until > *since. Same optional dedup.
Dedup is inside each query. An expired row and an active row for the same scope+type+value can both be returned on one payload.
