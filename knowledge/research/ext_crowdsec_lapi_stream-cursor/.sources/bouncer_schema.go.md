---
url: https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/database/ent/schema/bouncer.go
title: Bouncer schema stream_cursor and last_pull
fetched: 2026-09-05
authority: source
ref: github.com/crowdsecurity/crowdsec@e5da1b24a5dc0311ddcab74a5522b8feafbcbaee:pkg/database/ent/schema/bouncer.go
---

name: unique, immutable.
api_key: sensitive (hash of api key). Not unique by itself.
last_pull: Time, nillable, optional.
stream_cursor: Int, default 0. Comment: highest decision id already streamed to this bouncer. Distinct from last_pull (wall-clock heartbeat). A decision can commit after a pull that could not see it yet, so a timestamp can never be a safe cursor.
Indexes: (api_key, auth_type), (api_key, ip_address), (last_pull, created_at). No unique on api_key alone.
