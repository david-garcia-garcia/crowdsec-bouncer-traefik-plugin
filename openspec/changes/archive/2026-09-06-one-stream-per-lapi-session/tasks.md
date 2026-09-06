## 1. Reclaim Peek, Sleep/Wake, PeekLivePrefix

- [x] 1.1 Add `Peek(key)` (value, holders, sleeping, ok) without binding
- [x] 1.2 Last holder calls `Sleep()`; Open during grace calls `Wake()`; grace `Close()`s
- [x] 1.3 `PeekLivePrefix(prefix)` returns one live slot under the stem (ignore sleepers; no Close/DropNow)
- [x] 1.4 Tests: peek during sleep; Sleep then Wake on reclaim; PeekLivePrefix prefers live over sleeper; grace Close after Sleep

## 2. Stream session key and OpenStream

- [x] 2.1 Split session vs settings snapshot in `pkg/crowdsecconnection` with comments on LAPI cursor (key+IP)
- [x] 2.2 `SessionPrefix` / `SessionHex` for cache and live-sibling lookup; `SessionKey` = prefix + settings hash; live/none keep `Key` / `IdentityHex`
- [x] 2.3 `OpenStream`: PeekLivePrefix → live mismatch warn-and-wire that key; else Open own SessionKey (Wake or create)
- [x] 2.4 Store owner middleware name and snapshot on the connection for the warning; take ownership of a sleeper
- [x] 2.5 `plugin.go` uses `OpenStream` for stream/alone and `reclaim.Open`+`Key` for live/none/appsec
- [x] 2.6 `CrowdsecConnection.Sleep` / `Wake` stop and resume stream and metrics tickers

## 3. Tests and docs

- [x] 3.1 Unit: same LAPI key, metrics interval 1 vs 600 → same `SessionPrefix`, different `SessionKey`; different hosts → different keys
- [x] 3.2 Plugin: two live `New` stream configs same key different metrics → one connection, one ticker
- [x] 3.3 Plugin: cancel last holder, `New` with different snapshot within grace → old ticker stopped before new poll
- [x] 3.4 Plugin: different LAPI hosts still both poll
- [x] 3.5 Usage: `core_plugin_middleware.md`, `core_cache_client.md`, `build_e2e_real.md`; drop e2e `/trusted` forced metrics match if still present
- [x] 3.6 Comments: WHY on session, warn-and-wire, Sleep/Wake vs grace Close
