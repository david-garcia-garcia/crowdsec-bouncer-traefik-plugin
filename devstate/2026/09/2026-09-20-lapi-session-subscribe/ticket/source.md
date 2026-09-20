Title: Stream Client reclaim is LAPI session; join WARNs and subscribes; Wake keeps the DecisionStore

Operators can attach two CrowdSec middlewares in one Traefik process with the same LAPI host and API key but different Redis (or other session-owned knobs). CrowdSec stores one GET /v1/decisions/stream cursor and usage-metrics on the bouncer row selected by hashed X-Api-Key plus the IP LAPI sees (this process's outbound address). A second in-process ticker on that row steals startup=false deltas and POSTs a second metrics window.

Today stream Open key is SessionKey = SessionHex (mode + LAPI scheme/host/path + lapiKey) plus a hash of Redis store params. Different Redis ⇒ new lapi.Client ⇒ second ticker. Intervals already share silently (first-wins). OpenStream opens DecisionStore first then Client; those keys stay in lockstep only because both include Redis. Joiner logs INFO adopted only when transport replaced; Redis split is silent isolation that contradicts LAPI physics.

Desired:
1. Stream/alone Client reclaim key is the LAPI session (scheme+host+path+lapiKey, and mode), NOT Redis, NOT Traefik middleware name, NOT outbound IP, NOT host alone (two keys on one host must stay two Clients).
2. Join vs reconfigure is reclaim table state, not middleware name. Traefik New is per router: many New calls share one middleware name. Live holders → subscribe. Sleep/grace → Wake (startup=false, store+cursor kept). Empty → create.
3. Client records live holder middleware names as a set (same idea as liveHeaderScopes) so WARN can name who joined whom. Not a single ownerName.
4. Subscribe (live sibling): reuse the existing Client and its DecisionStore. Do not fail New. First-wins for session-owned knobs. WARN listing every ignored field and that isolation requires a second bouncer API key. Session-owned at least: redisCacheEnabled/host/password/database/read hosts, updateIntervalSeconds, metricsUpdateIntervalSeconds, updateMaxFailure, CAPI scenarios. Per-router stays on Bouncer (failure actions, templates, trusted IPs, Enabled, captcha). TLS/timeout stay AdoptTransport last-wins. decisionScopeHeaders stay live union.
5. Wake/reconfigure: keep DecisionStore and CrowdSec cursor; do not startup=true because YAML changed. AdoptTransport already. Redis YAML change on Wake keeps the live store and WARNs; no migrate memory↔Redis in this ticket.
6. DecisionStore is opened in Client create() (child of the Client incarnation), not a sibling reclaim Open in plugin.go/OpenStream. Otherwise dropping Redis from the Client key leaks a zombie store on join. Store Close stays the Client Close hook. StoreKey/Redis prefix/SessionHex for Redis keys must remain reachable (no Redis key migration).
7. Operator surface: WARN on subscribe mismatch (fields + middleware names + second API key). INFO on first create that this LAPI key owns the process-wide stream/metrics. README: one key = one ticker + one metrics window in this instance; Redis/interval disagreements are ignored, not isolated.

Out of scope: two Traefik processes (reclaim is process-local; docs only). Migrating a live store between Redis hosts. Failing New on conflict. Keying Client by LAPI host alone. Using one middleware name to detect reload. Peek/PeekLivePrefix/warn-and-wire sibling slots (those were removed).

Open for explore (do not bake in requirement as decided): whether stream+live on the same key should share one metrics reporter; whether live/none Client Key also drops Redis the same way.
