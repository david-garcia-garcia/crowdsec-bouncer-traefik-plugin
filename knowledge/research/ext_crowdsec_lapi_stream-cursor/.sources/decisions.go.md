---
url: https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/apiserver/controllers/v1/decisions.go
title: StreamDecision stream cursor
fetched: 2026-09-05
authority: source
ref: github.com/crowdsecurity/crowdsec@e5da1b24a5dc0311ddcab74a5522b8feafbcbaee:pkg/apiserver/controllers/v1/decisions.go
---

writeDecisions: paginates by id from startID (limit 30000). Comment: a startup resync passes 0, a stream delta passes the bouncer cursor; both are the same query, they only differ in where they start. lastId > 0 sets filters["id_gt"].

streamDecisions: writes {"new":[...],"deleted":[...]}. Comment: active decisions; a startup resync is this same query with a zero cursor (QueryAllDecisionsWithFilters). Expired keyed on until, not the cursor. If !startup, QueryExpiredDecisionsSinceWithFilters with since = LastPull.Add(-2s) when LastPull != nil (2-second overlap). Expired writeDecisions always starts at 0.

StreamDecision: getBouncerFromContext. HEAD: 200 empty, no last-pull update (would mess the next delta without startup=true). Missing scopes → ip,range. startup = query startup=="true". Snapshots LatestDecisionID before streaming (uncommitted insert gets a higher id). cursor := bouncerInfo.StreamCursor; if startup || cursor > latestID { cursor = 0 }. On stream err==nil: UpdateBouncerStreamPull(Background, streamStartTime, latestID, bouncerInfo.ID). Does not store writeDecisions lastId.
