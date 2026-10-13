---
url: https://docs.crowdsec.net/docs/next/local_api/bouncers.md
title: For Remediation Components
fetched: 2026-09-05
authority: official
---

Bouncers authenticate with X-Api-Key (cscli bouncers add). Missing/incorrect token → 403.
Remediation methods are restricted to /decisions. Two modes: stream (regular fetch of new and expired decisions) and query (specific ip/range/username).
Stream endpoint: /decisions/stream with a single startup boolean. true = full state of decisions; false = update since it last pulled.
startup=true example includes a large deleted list (past deleted events) plus current new (local and CAPI). Intended so LAPI restart does not desync bouncers.
startup=false immediately after: deleted null, new null when nothing changed.
This page does not name stream_cursor, last_pull, per-row storage, or auto-created per-IP bouncer rows.
