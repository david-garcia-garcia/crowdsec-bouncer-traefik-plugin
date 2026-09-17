# LAPI stream cursor

Where CrowdSec LAPI stores `/v1/decisions/stream` progress, which bouncer row owns that cursor, what `startup=true` does, and what happens when two HTTP clients poll `startup=false` at once.

Fetched: 2026-09-05. Engine pin: `github.com/crowdsecurity/crowdsec@e5da1b24a5dc0311ddcab74a5522b8feafbcbaee`.

## Where LAPI stores the cursor

The stream cursor is a column on the **bouncer** database row, not a per-HTTP-connection or per-API-key-string object.

- Column `stream_cursor` (Go `StreamCursor`, `int`, default `0`). Schema comment: "Highest decision id already streamed to this bouncer." It is **not** `last_pull`. `last_pull` is a wall-clock heartbeat; "a timestamp can never be a safe cursor" because a decision can commit after a pull that could not see it yet. Owner: [bouncer schema](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/database/ent/schema/bouncer.go). Extract: `.sources/bouncer_schema.go.md`
- Generated ent fields: `LastPull *time.Time`, `StreamCursor int`. Owner: [ent Bouncer](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/database/ent/bouncer.go) (generated from the schema). Extract: `.sources/bouncer.go.md`
- `GET /v1/decisions/stream` reads `cursor := bouncerInfo.StreamCursor`. After a successful stream (no write error), LAPI calls `UpdateBouncerStreamPull(ctx, streamStartTime, latestID, bouncerInfo.ID)`. That writes **both** `last_pull` and `stream_cursor` on **that row id**. The stored cursor is `LatestDecisionID()` taken **before** streaming, not the last id emitted in the JSON. Owner: [StreamDecision](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/apiserver/controllers/v1/decisions.go); [UpdateBouncerStreamPull](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/database/bouncers.go). Extracts: `.sources/decisions.go.md`, `.sources/bouncers.go.md`

`LatestDecisionID` is `max(decision.id)` (or `0` if the table is empty). The controller snapshots it first so an uncommitted insert cannot be stepped over: it will get a higher id and appear on the next pull. Owner: [StreamDecision](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/apiserver/controllers/v1/decisions.go); [LatestDecisionID](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/database/decisions.go). Extract: `.sources/decisions_db.go.md`

The `new` array is `QueryAllDecisionsWithFilters` (`until > now`) paginated with `id_gt` = cursor (`decision.IDGT`). A zero cursor omits `id_gt` and returns the full active set (30 000 per page). Owner: [writeDecisions](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/apiserver/controllers/v1/decisions.go); [id_gt](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/database/decisionfilter.go). Extract: `.sources/decisionfilter.go.md`

## Owner is the bouncer row, not the API key string

`StreamDecision` uses the `*ent.Bouncer` the API-key middleware put in gin context. `UpdateBouncerStreamPull` updates `UpdateOneID(id)`. There is no cursor table keyed by the plaintext API key. Owners: [getBouncerFromContext](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/apiserver/controllers/v1/utils.go); [api_key middleware](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/apiserver/middlewares/v1/api_key.go). Extracts: `.sources/utils.go.md`, `.sources/api_key.go.md`

`api_key` on the row is the **SHA-512 hex of** `X-Api-Key`. Several rows may share that hash: the schema indexes `(api_key, auth_type)` and `(api_key, ip_address)` and does **not** unique the key alone. `name` is unique. Owner: [bouncer schema](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/database/ent/schema/bouncer.go)

How `authPlain` picks the row (API-key auth, not TLS):

1. Look up hash + `ClientIP()` (`SelectBouncerWithIP`). Hit → that row (that cursor).
2. Else list rows with that hash (`SelectBouncers`, ordered by id). If exactly one row and its `ip_address` is empty, reuse it (first request; middleware then stamps the IP).
3. Else **create** a new row `base@<clientIP>` with the same hashed key and `auto_created=true`. Comment: when a bouncer changes IP, LAPI treats it as a new bouncer **to allow for key sharing**.

Owner: [api_key.go](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/apiserver/middlewares/v1/api_key.go); [SelectBouncers](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/database/bouncers.go)

So: **same key + same client IP as LAPI sees it → same row → shared cursor.** Same key from a **new** IP → a second row with its own `stream_cursor` / `last_pull`. Two Traefik pods that NAT to one address share one cursor; pods that present distinct source IPs do not.

**Official vs source (docs omit row ownership):** the remediation-component page never names `stream_cursor`. It talks as if `/decisions/stream?startup=` is "full state" vs "an update since it last pulled" for that API token. Follow source for this version. Owner of the incomplete description: [LAPI bouncers](https://docs.crowdsec.net/docs/next/local_api/bouncers.md). Extract: `.sources/lapi_bouncers.md`

## `startup=true`

Official: `/decisions/stream` has a single `startup` boolean. `true` = full state of decisions; `false` = update since last pull. The first `startup=true` body includes a large `deleted` list (past expirations) so a restart does not desync. A `startup=false` call immediately after can be `new`/`deleted` null. Owner: [LAPI bouncers](https://docs.crowdsec.net/docs/next/local_api/bouncers.md)

Source (what this pin does):

- Query param: `startup := ok && val[0] == "true"` (any other value, including absent, is not startup).
- `if startup || cursor > latestID { cursor = 0 }`. Zero cursor is also used when the stored cursor is past the table (partial restore / MySQL `< 8.0` AUTO_INCREMENT rewind).
- Comment on `writeDecisions`: "A startup resync passes 0, a stream delta passes the bouncer cursor: both are the same query, they only differ in where they start."
- Comment on `streamDecisions`: "Active decisions. A startup resync is this same query with a zero cursor."
- `deleted` on startup uses `QueryExpiredDecisionsWithFilters` (all `until < now` matching filters), **not** the `last_pull` window. Non-startup uses `QueryExpiredDecisionsSinceWithFilters` with `since = LastPull.Add(-2s)` when `LastPull != nil`. Comment: 2-second overlap "to avoid missing decisions that expired around the last pull time". Expired path always passes `startID 0` to `writeDecisions` (not the stream cursor). Owner: [decisions.go](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/apiserver/controllers/v1/decisions.go); [decisions_db](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/database/decisions.go)

A successful startup still calls `UpdateBouncerStreamPull` with `latestID`. The next `startup=false` therefore starts from that snapshot id.

HEAD on `/decisions/stream` returns 200 with no body and **does not** update last pull / cursor. Comment: an update would mess with the next delta if done without `startup=true`. Owner: [StreamDecision](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/apiserver/controllers/v1/decisions.go)

## Two clients polling `startup=false` concurrently

LAPI does **not** take a lease, lock, or compare-and-swap on `stream_cursor`. `UpdateBouncerStreamPull` is `UpdateOneID(id).SetLastPull(...).SetStreamCursor(...)`.

If both requests resolve to the **same row** (same hashed key + same `ClientIP()`):

1. Middleware loads one `*ent.Bouncer` snapshot (`StreamCursor`, `LastPull`) per request.
2. Each `StreamDecision` reads that snapshot, snapshots `latestID`, streams `id_gt = cursor`, and on success overwrites the same row.
3. Both responses can contain the same `new` ids (`id_gt` from the same cursor) and the same `deleted` window (`LastPull-2s` from the same snapshot).

Authority **inference** (files read: [StreamDecision](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/apiserver/controllers/v1/decisions.go), [UpdateBouncerStreamPull](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/database/bouncers.go)): last writer wins. If the request that sampled a **smaller** `latestID` finishes last, `stream_cursor` moves backward; the next delta re-sends those ids (duplicates, not a silent skip of `new`). If `last_pull` is written backward, the next deleted window is wider (duplicate deletes). A miss of `new` from this race is not what the id cursor does; a miss of `deleted` would require the last writer to advance `last_pull` past an expiry that neither response included, which the 2-second overlap is meant to shrink, not eliminate under arbitrary clock gaps.

If the two clients resolve to **different rows** (same key, different IPs), each row has its own cursor. Concurrent `startup=false` polls do not advance each other's `stream_cursor`. Each client is a separate stream consumer. Owner: [api_key.go](https://github.com/crowdsecurity/crowdsec/blob/e5da1b24a5dc0311ddcab74a5522b8feafbcbaee/pkg/apiserver/middlewares/v1/api_key.go) (key-sharing create).

Official docs do not describe this race or per-IP rows.

## References

- Official: [LAPI for remediation components](https://docs.crowdsec.net/docs/next/local_api/bouncers.md)
- Source: `github.com/crowdsecurity/crowdsec@e5da1b24` paths listed above
- Extracts: `.sources/`
