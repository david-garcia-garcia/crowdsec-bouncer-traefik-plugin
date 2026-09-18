---
url: https://github.com/crowdsecurity/crowdsec/blob/a8dbeb94efb61c417b556b5468a7695a9410cb2f/pkg/apiserver/controllers/v1/decisions.go
title: LAPI streamDecisions JSON
fetched: 2026-09-18
authority: source
ref: github.com/crowdsecurity/crowdsec@a8dbeb94efb61c417b556b5468a7695a9410cb2f:pkg/apiserver/controllers/v1/decisions.go
---

streamDecisions writes {"new": [ then QueryAllDecisionsWithFilters (active, cursor), then ], "deleted": [ then expired query, then ]}.
Wire field order is new then deleted. Docs examples list deleted then new. Follow this pin for the wire.
new and deleted are two queries. No step intersects or drops a value that appears in both.
Expired: startup uses QueryExpiredDecisionsWithFilters; delta uses QueryExpiredDecisionsSinceWithFilters with LastPull-2s. Expired writeDecisions always starts at 0 (not the stream cursor).
Comment: expired are keyed on until, not on the cursor.
