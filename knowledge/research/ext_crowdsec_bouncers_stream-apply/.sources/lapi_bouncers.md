---
url: https://docs.crowdsec.net/docs/next/local_api/bouncers.md
title: For Remediation Components
fetched: 2026-09-18
authority: official
---

Stream endpoint: /decisions/stream with a single startup boolean. true = full state of decisions; false = update since it last pulled.
startup=true example body includes a large deleted list (past deleted events) plus current new. Intended so LAPI restart does not desync bouncers.
The printed example lists "deleted" then "new". The page does not name apply order, stream_cursor, or same-value overlap between the two arrays.
startup=false immediately after can be deleted null, new null.
