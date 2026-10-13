# Store more than one CrowdSec decision per cache key

IssueKey: 2026-09-19-real-e2e-coverage
PR: https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/117
Size: large
Action: note

## Why this follow-up

CrowdSec LAPI returns **several rows for the same identity** (same IP, or the same header-scope value). Examples: community-list ban + local ban, ban + captcha, ban + `type=allow`, each with its own `id`, `origin`, and `duration`. Stream `deleted` then names **one** of those rows.

This plugin stores **one payload per cache key**. Stream `storeStreamDecision` `Set`s the IP (or header-scope) slot; the next New for that slot overwrites. Stream `deleteStreamDecision` `Delete`s the whole slot. Live/none `strongestLiveDecision` walks the LAPI array and returns the first `ban`, else the first `captcha`; `type=allow` is not a remediation letter (`RemediationValue` is empty) so it never wins and never vetoes.

That last-write / first-ban model cannot:

- keep a ban when a co-located allow is later deleted
- keep captcha when a co-located ban is deleted
- keep a second ban when the first expires or is deleted
- honour independent CrowdSec durations on two rows for the same IP

Fixing allow-over-ban (or any typed delete) without changing the slot shape just writes a merged effective value into the same key. That is wrong: when stream later deletes only the allow, the ban must still be there.

## Why it was not taken

This is a DecisionStore / cache contract change (`Set`/`Get`/`GetInt` today are one opaque `string` or one `uint32` per key, one TTL per key). It touches stream apply, live pick, lookup merge, Redis STRING+EXPIRE, Yaegi, and metrics origin intern. PR 117 is real-stack e2e coverage, not that product change. The failing allow-over-ban cases were removed from the suite so CI is not held red; they are recovered below.

## Risks

Leaving last-write-wins: CrowdSec `type=allow` next to a ban still 403s (measured on this PR). Two bans / ban+captcha for one IP still collapse. A later “just write `f` when allow is present” patch would drop the ban when allow is deleted.

Implementing a two-STRING split (`ip` = one remediation, `allow:ip` = allow marker) only models **two facts** and still smashes two bans or ban+captcha. Do not take that shortcut if the requirement is N live rows.

## Context

### Observed on the parked test

- LAPI `GET /v1/decisions?ip=` for a test IP with `cscli decisions add --type ban` and `--type allow` returns **both JSON rows**.
- None mode `/whoami`: expected 200, got 403. `queryLiveDecisions` → `strongestLiveDecision` returns the ban.
- Stream mode `/stream`: stream applies the ban (`Set` packed `t`), then skips `type=allow` (`storeStreamDecision` returns on empty `RemediationValue`). Expected 200 after allow, leftover 403.
- Official CrowdSec **allowlists** (`cscli allowlists`) delete bans at LAPI; that is a different feature. This debt is about **multiple decision rows** still present on LAPI, including `type=allow`. Product still needs a lookup rule for allow-as-veto once N rows can be stored.

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

Cache spec (`openspec/specs/core_cache_client_decision-store/spec.md`): payloads stay opaque `string` or `uint32`; the cache package must not know remediation names. A list-of-rows encoding is a **caller** contract (lapi/decisionscope), or a new cache API. Do not teach `cache` the letters `t`/`c`/`allow`.

### Required shape: `slot → []row`, not `slot → compacted`

A packed `[]uint32` is not enough. Stream `deleted` is keyed by CrowdSec `Decision.ID` (JSON field `id` on `lapi.Decision`). Each row needs at least:

```text
{ id int, compacted uint32 | leftover letter+origin, expiresAt unix }
```

Lookup on a slot: drop expired rows; if any remaining row is `type=allow` (once that type is stored), pass; else `PreferRemediation` across remaining ban/captcha. Stream New appends or replaces by `id`. Stream Deleted removes by `id`; empty list deletes the key.

Writing the **effective** remediation into the same key (allow present → store `f`) is not this shape: allow removal would leave a pass with no ban.

### Redis: one STRING (or HASH) whose value is the list

Keep **one Redis key per slot** (same `IPCacheKey` / `HeaderScopeKey` as today) so the request path stays **one GET**. Encode the row list in the STRING (or HASH field = decision id, value = compacted + expiry). Redis `EXPIRE` / `PEXPIRE` is still on the **key**: set it to `max(remaining row TTLs)` only to drop an empty key; **Get must filter stale rows**. `EX` = min would drop a 4h ban when a 10m allow expires. `EX` = max without filtering would keep allow in the blob after CrowdSec expired it.

Add/delete is **read-modify-write**. Two pollers (or stream + live) race on GET → patch → SET. Use one Lua `EVAL`/`EVALSHA` (Lua 5.1, same style as `pkg/cache/acquire.go`): load, drop matching `id` and expired rows, append, `PEXPIRE` to the new max, `DEL` if empty. Prefix every key with `SessionHex` as today.

Memory `ttl_map` has the same one-timestamp-per-key limit: store per-row `expiresAt` in the value; the heap TTL is the max.

`GetInt` as “this key is one word” does not survive. Lookup must decode the list. Cardinality is usually tiny; the cost is decode + merge + Lua on stream deltas, not extra GET on the hit path.

### Approaches that do not hold

| Approach | Why not |
|---|---|
| Two STRINGs `ip` + `allow:ip` | Only two facts. Two bans or ban+captcha still overwrite. Independent allow TTL is solved; N rows are not. |
| One Redis key per `decision id` with no index | Lookup cannot find the ids without SCAN or a second index key (more races, more round-trips). |
| Redis LIST of packed words | Delete-by-id is a rewrite anyway; no per-element TTL. |
| Redis HASH without expiry in the field | Dragonfly 1.40: do not assume `HEXPIRE`. Same per-row expiry-in-value + key max TTL as STRING. |
| `[]uint32` only | Cannot delete one of two same-origin bans; no per-row duration. |

### Suggested apply order when this is taken

1. Change stream store/delete to append/remove by `Decision.ID` with per-row expiry (memory first).
2. Redis: encode the same list in one STRING; Lua for New/Deleted; `GetInt` hot path replaced on those keys.
3. Live/none: do not collapse with `strongestLiveDecision` before cache write if live cache must survive a later typed delete; or keep live as a query-time merge of the LAPI array (N rows exist on the wire already) and only fix stream persistence.
4. Lookup: allow-veto then ban-over-captcha across remaining rows.
5. Restore the Pester file below; re-add the e2e spec requirement that PR 117 parked.
6. Cover stream: ban+allow, delete allow, ban remains; two bans, delete one, the other remains; ban+captcha typed delete.

### Restore the real-stack test

Removed from `tests/e2e/real/allow_decisions.Tests.ps1` (PR 117) so the suite is not red on a product gap. Copy the block in [Recovered Pester file](#recovered-pester-file) back to that path. `Test-Integration.ps1` picks up `*.Tests.ps1` automatically. Helpers `Add-TestDecision`, `Remove-AllTestDecisions`, `/whoami` (none) and `/stream` already exist in `tests/e2e/real/TestUtils.ps1` and compose.

Also restore the `build_e2e_pester_crowdsec-stack` requirement “Real stack covers CrowdSec allow as a whitelist” (allow-only + allow-over-ban none and stream) that was deleted with this note.

## Recovered Pester file

Save as `tests/e2e/real/allow_decisions.Tests.ps1`.

```powershell
#!/usr/bin/env pwsh

# CrowdSec allow decisions are a whitelist: an IP with type=allow must pass even
# when a ban for the same IP exists. cscli writes both; the plugin must not let
# the ban win.

BeforeAll {
    . "$PSScriptRoot/TestUtils.ps1"

    $script:TraefikUrl = "http://localhost:8000"
    $script:CrowdSecApiUrl = "http://localhost:8081"
    $script:ApiKey = "40796d93c2958f9e58345514e67740e5"
    $script:NoneIP = "10.82.0.10"
    $script:StreamIP = "10.82.0.11"

    $result = Wait-ForCondition -Description "CrowdSec LAPI to be ready" -TimeoutSeconds 60 -RetryIntervalSeconds 2 -Condition {
        Invoke-CrowdSecAPI -Endpoint "/v1/decisions?limit=1" -TimeoutSec 5 -ApiKey $script:ApiKey -CrowdSecApiUrl $script:CrowdSecApiUrl
        return $true
    }
    if (-not $result.Success) {
        throw "CrowdSec LAPI failed to become ready"
    }
}

Describe "CrowdSec allow decisions" {
    Context "Allow is a whitelist" -Tag "allow" {
        BeforeEach {
            Clear-TraefikAccessLogs
            Remove-AllTestDecisions
        }

        It "Should not remediate an IP that only has an allow decision" {
            Add-TestDecision -IP $script:NoneIP -Type "allow"

            $response = Test-HttpRequest -Endpoint "/whoami" -IP $script:NoneIP -TraefikUrl $script:TraefikUrl
            $response.StatusCode | Should -Be 200 -Because "type=allow is not a ban or captcha"
        }

        It "Should let an allow decision whitelist a banned IP in none mode" {
            Add-TestDecision -IP $script:NoneIP -Type "ban"
            Add-TestDecision -IP $script:NoneIP -Type "allow"

            $banned = Test-HttpRequest -Endpoint "/whoami" -IP $script:NoneIP -TraefikUrl $script:TraefikUrl
            $banned.StatusCode | Should -Be 200 -Because "CrowdSec type=allow must whitelist the same IP over a ban; a 403 means strongestLiveDecision picked ban and ignored allow"
        }

        It "Should let an allow decision whitelist a banned IP in stream mode" {
            Add-TestDecision -IP $script:StreamIP -Type "ban"
            Add-TestDecision -IP $script:StreamIP -Type "allow"

            $blocked = Wait-ForCondition -Description "stream to see the ban for $($script:StreamIP)" -TimeoutSeconds 30 -RetryIntervalSeconds 2 -Condition {
                $response = Test-HttpRequest -Endpoint "/stream" -IP $script:StreamIP -TraefikUrl $script:TraefikUrl
                return ($response.StatusCode -in @(403, 429))
            }
            if ($blocked.Success) {
                $whitelisted = Wait-ForCondition -Description "stream to honour allow over ban for $($script:StreamIP)" -TimeoutSeconds 30 -RetryIntervalSeconds 2 -Condition {
                    $response = Test-HttpRequest -Endpoint "/stream" -IP $script:StreamIP -TraefikUrl $script:TraefikUrl
                    return ($response.StatusCode -eq 200)
                }
                $whitelisted.Success | Should -Be $true -Because "stream must drop the ban when type=allow is present; a leftover 403 means allow was treated as an unknown stream type"
            }
            else {
                $response = Test-HttpRequest -Endpoint "/stream" -IP $script:StreamIP -TraefikUrl $script:TraefikUrl
                $response.StatusCode | Should -Be 200 -Because "if stream never applied the ban, allow already won"
            }
        }
    }
}
```
