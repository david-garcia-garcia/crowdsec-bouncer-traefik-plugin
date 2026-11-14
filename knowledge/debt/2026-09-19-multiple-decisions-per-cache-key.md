# Store more than one CrowdSec decision per cache key

IssueKey: 2026-09-19-real-e2e-coverage
PR: https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/117
Size: large
Action: note

## Why this follow-up

CrowdSec LAPI returns **several rows for the same identity** (same IP, or the same header-scope value). Examples: community-list ban + local ban, or ban + captcha, each with its own `id`, `origin`, and `duration`. Stream `deleted` then names **one** of those rows.

This plugin stores **one payload per cache key**. Stream `storeStreamDecision` `Set`s the IP (or header-scope) slot; the next New for that slot overwrites. Stream `deleteStreamDecision` `Delete`s the whole slot. Live/none `strongestLiveDecision` walks the LAPI array and returns the first `ban`, else the first `captcha`, by ingest kind. A type that is neither `ban` nor `captcha` follows `lapiRemediationFallback` (`core_plugin_lapi_remediation-fallback`): stored as ban or captcha, or not stored under `ignore`.

That last-write / first-ban model cannot:

- keep captcha when a co-located ban is deleted
- keep a second ban when the first expires or is deleted
- honour independent CrowdSec durations on two rows for the same IP

Fixing a typed delete without changing the slot shape just writes a merged effective value into the same key. That is wrong: when stream later deletes only one row, the other rows must still be there. Under `lapiRemediationFallback: ban` or `captcha`, a stream Deleted row of an unknown type still clears the whole slot or CIDR; only `ignore` makes it a no-op.

## Why it was not taken

This is a DecisionStore / cache contract change (`Set`/`Get`/`GetInt` today are one opaque `string` or one `uint32` per key, one TTL per key). It touches stream apply, live pick, lookup merge, Redis STRING+EXPIRE, Yaegi, and metrics origin intern. PR 117 is real-stack e2e coverage, not that product change.

## Risks

Leaving last-write-wins: two bans / ban+captcha for one IP still collapse, and a typed Deleted row clears the whole slot.

Implementing a two-STRING split per slot only models **two facts** and still smashes two bans or ban+captcha. Do not take that shortcut if the requirement is N live rows.

## Context

### What LAPI returns

- LAPI `GET /v1/decisions?ip=` for an IP with two `cscli decisions add` rows returns **both JSON rows**.
- Stream mode: each New row overwrites the slot; a Deleted row drops the whole slot. Unknown types follow `lapiRemediationFallback` (stored as ban or captcha, or skipped on New and Deleted under `ignore`).
- `whitelist` and `allow` are not valid CrowdSec decision types; the LAPI stream says what to block, not what to allow. Allowing traffic belongs to parser whitelists and LAPI allowlists (`cscli allowlists`), which stop or expire decisions at the source. This debt is about **multiple remediation rows** on one key, not an allow veto.

### Current storage (one key, one word, one TTL)

| Path | What happens |
|---|---|
| Stream New | `pkg/lapi/client_decisions.go` `storeStreamDecision`: `IPCacheKey` / `HeaderScopeKey` → `cache.Set(slot, Pack(kind, origin), durationSeconds)` |
| Stream Deleted | `deleteStreamDecision`: `Delete` that slot (and the raw IP string for IP scope) |
| Live/none | `queryLiveDecisions` picks **one** row via `strongestLiveDecision`, then caches that one letter |
| Memory | `ttl_map` entry: payload `uint32` (`packWord`: `kind[0] \| originID<<8`) or leftover string; **one heap expiry** |
| Redis | Dragonfly STRING: `SET key value EX seconds` (`pkg/cache/cache.go` `redisCache.set`). `GetInt` parses decimal ASCII `uint32`. Prefix is `SessionHex`. **One EXPIRE on the key** |
| Lookup | `GetInt` then maybe `Get`; `PreferRemediation` is ban > captcha > empty across **different** keys (IP vs Range vs header), not across rows **inside** one key |

`Pack` does not store CrowdSec `Decision.ID`. Two bans from the same interned origin are the same word. Typed stream delete cannot target one of them.

Range CIDRs are a **different** identity (`range-index` + membership). This debt is N rows on **one** IP or header-scope key. Lookup already merges across keys; it cannot un-smash a slot that only kept the last write.

Cache spec (`openspec/specs/core_cache_client_decision-store/spec.md`): payloads stay opaque `string` or `uint32`; the cache package must not know remediation names. A list-of-rows encoding is a **caller** contract (lapi/decisionscope), or a new cache API. Do not teach `cache` the letters `t`/`c`.

### Required shape: `slot → []row`, not `slot → compacted`

A packed `[]uint32` is not enough. Stream `deleted` is keyed by CrowdSec `Decision.ID` (JSON field `id` on `lapi.Decision`). Each row needs at least:

```text
{ id int, compacted uint32 | leftover letter+origin, expiresAt unix }
```

Lookup on a slot: drop expired rows; `PreferRemediation` across remaining ban/captcha. Stream New appends or replaces by `id`. Stream Deleted removes by `id`; empty list deletes the key.

Writing the **effective** remediation into the same key is not this shape: removing one row would lose the others.

### Redis: one STRING (or HASH) whose value is the list

Keep **one Redis key per slot** (same `IPCacheKey` / `HeaderScopeKey` as today) so the request path stays **one GET**. Encode the row list in the STRING (or HASH field = decision id, value = compacted + expiry). Redis `EXPIRE` / `PEXPIRE` is still on the **key**: set it to `max(remaining row TTLs)` only to drop an empty key; **Get must filter stale rows**. `EX` = min would drop a 4h ban when a 10m captcha expires. `EX` = max without filtering would keep the captcha in the blob after CrowdSec expired it.

Add/delete is **read-modify-write**. Two pollers (or stream + live) race on GET → patch → SET. Use one Lua `EVAL`/`EVALSHA` (Lua 5.1, same style as `pkg/cache/acquire.go`): load, drop matching `id` and expired rows, append, `PEXPIRE` to the new max, `DEL` if empty. Prefix every key with `SessionHex` as today.

Memory `ttl_map` has the same one-timestamp-per-key limit: store per-row `expiresAt` in the value; the heap TTL is the max.

`GetInt` as “this key is one word” does not survive. Lookup must decode the list. Cardinality is usually tiny; the cost is decode + merge + Lua on stream deltas, not extra GET on the hit path.

### Approaches that do not hold

| Approach | Why not |
|---|---|
| Two STRINGs per slot | Only two facts. A third row still overwrites; N rows are not solved. |
| One Redis key per `decision id` with no index | Lookup cannot find the ids without SCAN or a second index key (more races, more round-trips). |
| Redis LIST of packed words | Delete-by-id is a rewrite anyway; no per-element TTL. |
| Redis HASH without expiry in the field | Dragonfly 1.40: do not assume `HEXPIRE`. Same per-row expiry-in-value + key max TTL as STRING. |
| `[]uint32` only | Cannot delete one of two same-origin bans; no per-row duration. |

### Suggested apply order when this is taken

1. Change stream store/delete to append/remove by `Decision.ID` with per-row expiry (memory first).
2. Redis: encode the same list in one STRING; Lua for New/Deleted; `GetInt` hot path replaced on those keys.
3. Live/none: do not collapse with `strongestLiveDecision` before cache write if live cache must survive a later typed delete; or keep live as a query-time merge of the LAPI array (N rows exist on the wire already) and only fix stream persistence.
4. Lookup: ban-over-captcha across remaining rows.
5. Cover stream: two bans, delete one, the other remains; ban+captcha typed delete.
