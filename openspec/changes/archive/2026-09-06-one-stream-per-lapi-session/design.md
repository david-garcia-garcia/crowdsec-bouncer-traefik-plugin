## Context

See proposal.md — Why. LAPI stores `stream_cursor` on the bouncer row (key hash + `ClientIP()`), not per HTTP client and not per `scopes=`. `reclaim.Open` binds Traefik `New` ctx. Grace exists because reload cancels ctx then opens again with zero holders in between. Today `Key()` hashes intervals into identity, so a metrics mismatch is two keys and two pollers. A Redis-host change is also two keys, so grace keeps the old ticker running beside the new one for 10s.

## Goals / Non-Goals

**Goals:**
- At most one stream/alone poller per Traefik process per LAPI session.
- Warn-and-wire a second middleware on that session (first snapshot wins, log the ignored knobs).
- Unchanged reload Sleeps then Wakes (grace does not Close). Changed snapshot with no live holder: new reclaim key, old sleeper dies on grace.
- Comments that state LAPI cursor = key+IP and the reclaim assumptions.

**Non-Goals:**
- Cross-process in-memory uniqueness (same key + same LAPI-visible IP already shares a CrowdSec row; Redis is the multi-instance store).
- Failing `New` on knob mismatch (operators chose warn-and-wire).
- Moving AppSec HTTP client onto Bouncer.
- Plugin fail-closed origins, parse-once IP, range-index origin suffix.

## Decisions

1. **Session prefix** = mode (`stream`/`alone`) + LAPI scheme/host/path + lapiKey, or CAPI machine+password in alone. Not middleware name. TLS extras, Redis, intervals, AppSec, `decisionScopeHeaders` are the **settings snapshot**. `SessionKey` = that prefix plus settings hash so a sleeper does not block a new snapshot. Alternative: put scopes in the hash — that starts a second poller on the same CrowdSec cursor.

2. **Warn-and-wire** when `PeekLivePrefix` shows a live slot under the session prefix and the joiner’s `SessionKey` differs. Log owner middleware (`streamOwner` on the connection), joiner, and field names. `Open` the live key. Alternative: fail `New` — louder, takes the joiner router down.

3. **Sleep / Wake / grace Close.** Last holder → `Sleep()` (tickers off, object kept). `Open` during grace on the **same** key → `Wake()` (`startup=false`). Grace elapsed → table `Close()`s. Snapshot change on a sleeper → `Open` a new key (create). Callers do not Close slots. Unchanged snapshot: no extra `startup=true`. Alternative: keep tickers running during grace — reload gap would still poll, but a racing new snapshot could overlap.

4. **`Peek` / `PeekLivePrefix` on `pkg/reclaim`** (stdlib table). Exact Peek is same-key inspect. Prefix Peek is “this CrowdSec row already has a live holder.” Alternative: `sync.Once` — never disposes. Alternative: `ReplaceSleeping` — extra table dispose path when the key is session-only. Alternative: public `DropNow` — exposes slot Close.

5. **Stream Redis prefix = session hex.** Warn-and-wire must share cache keys. Live/none still use full `IdentityHex` / `Key()`.

6. **Live/none/appsec** do not take a stream session. Two live connections on one key remain OK (`?ip=` does not use `stream_cursor`).

## Risks / Trade-offs

- [First-wins scopes] → Country header middleware on the same key as a default stream bouncer will not expand `scopes=`. Log it. Second bouncer key remains the isolation path.
- [First-wins Redis while a sibling still holds] → changing Redis on one of two live middlewares is ignored until the owner incarnation is replaced. Log it.
- [Two first Opens race different hashes] → both can miss `PeekLivePrefix` and create; Open’s create-race only covers the same key. Same window as any first-put race.
- [Yaegi] → keep `New`/`CreateConfig` on the root package; `create` still takes no args.

## Migration Plan

Deploy as a plugin version bump. Operators with two stream middlewares on one key get one ticker and a warning if knobs differ. Rollback: previous tag restores two pollers. No JSON key rename.
