# Reclaim identity can start two stream pollers on one CrowdSec bouncer key

Why: CrowdSec GET /v1/decisions/stream is a per-API-key session (startup dump, then deltas). CrowdsecConnection is reclaimed by a config hash. Any identity field that is not that session still creates a second connection that polls the same key. The two pollers steal deltas; caches go empty; bans never apply. CI showed it when /stream set metricsUpdateIntervalSeconds=1 and /trusted kept default 600, same BOUNCER_KEY_TRAEFIK_TEST. That is not a test-only footgun. It is the reclaim model.

Invariant that is false today

At most one stream/alone poller (and one decision cache / range-index prefix) per Traefik process per stream session = LAPI URL + bouncer key + scopes= query (CAPI creds in alone).

Today the reclaim key is crowdsecconnection: + FNV of identityFrom (pkg/crowdsecconnection/identity.go). Spec core_plugin_middleware_instance-reclaim puts update and metrics intervals in that key on purpose so “two configs that disagree on interval get two connections, no first-wins globals.” Isolated backends only exist if they also have different LAPI keys (or hosts). Same key + two identities = two tickers, one session.

Today (evidence)

Identity includes: mode, LAPI/CAPI, UpdateIntervalSeconds, MetricsUpdateIntervalSeconds, UpdateMaxFailure, LapiFailureAction, StreamStartupBlock, DefaultDecisionSeconds, HTTPTimeoutSeconds, Redis*, AppSec client, TLS. Comment says middleware name, templates, trusted IPs, Enabled are out.
New → reclaim.Open(ctx, crowdsecconnection.Key(config), …) → startStream starts a ticker that crowdsecQuerys v1/decisions/stream?startup=…&scopes=… (connection_stream.go, connection_decisions.go streamQuery).
Redis keys are prefixed with that same IdentityHex. Two identities ⇒ two prefixes ⇒ two incomplete caches, not one shared cache.
decisionScopeHeaders is on the connection and changes scopes=, but is not in identity. Opposite bug: two middlewares that should be different sessions can share one poller (first New wins scopes). E2e already papered that with BOUNCER_KEY_TRAEFIK_SCOPES.
core_plugin_middleware.md gotcha: “Same connection fields share one ticker; different LAPI/mode/redis/interval are two Connections.” That sentence is the bug statement.
How it shows up

Operator has two stream middlewares, same crowdsecLapiKey, and they differ on any identity field (metrics interval, update interval, HTTP timeout, Redis on/off, failure action, …). Traefik logs two reclaim_put keys. cscli decisions add applies on one router and not the other, or on neither. Looks like “stream cache is broken.”

E2e: mode_stream.Tests.ps1 waited 30s for 403 on 172.19.0.1 after cscli ban; never blocked. Same failure mode as usage-metrics cases that wait for a /stream ban.

Do not

Treat “set the same metricsUpdateIntervalSeconds on /trusted” as the product fix. That only makes the e2e hashes match.
Remove metrics from identity and stop. UpdateIntervalSeconds (and Redis, timeout, failure action) split the same way.
“First-wins” a second stream ticker onto a connection with a different Redis prefix or different scopes query.
Start a second poller “because the spec wanted two intervals.” Two intervals with one key is invalid against LAPI.
Expand CIDRs, change plugin origin labels, or parse-once IP work.
Do (product)

Make stream session an explicit unique resource.

Suggested shape (smallest durable, change if evidence says otherwise):

Define session key: LAPI scheme/host/path + lapiKey (or CAPI machine+password in alone) + scopes= from NormalizeDecisionScopeHeaders. Put that in identity (scopes must be in the key; they are not today).
Stream/alone: at most one startStream per session key in-process. Second New with the same session and a conflicting identity field (metrics interval, update interval, redis, …) SHALL fail New with an error that names both middlewares’ fields, or reclaim the existing session connection and ignore the conflicting knobs only if you can prove they cannot diverge cache/ticker meaning (prefer fail; silent ignore is how this bug was born).
Live/none: no stream session; current “two connections, same key” is OK for lookups. Usage-metrics POST is also per bouncer key; do not start two metrics tickers on one key without deciding that on purpose.
Redis prefix for stream/alone must follow the session, not a leftover extra identity hash, or two “almost same” configs will not see each other’s decisions.
Rewrite spec core_plugin_middleware_instance-reclaim:
Keep “same session fields ⇒ one ticker.”
Replace “disagree on update interval ⇒ two connections” with: disagree on interval (or redis, metrics, failure action) with the same LAPI key+scopes is a config error, not two isolated backends. Isolated backends need a second bouncer key (already the scopes e2e pattern).
Usage packets: core_plugin_middleware.md identity gotcha; build_e2e_real.md (do not require matching metrics labels as the long-term story).
Tests

Unit: two Key(cfg) with same LAPI key+mode+host, differ only MetricsUpdateIntervalSeconds (and separately only UpdateIntervalSeconds) — today they differ; after the fix, either same key or New fails. Pin the chosen behavior.
Unit: decisionScopeHeaders different ⇒ different session key (must not first-win).
Unit/plugin: two New stream configs, same key, different metrics interval, live constructor ctxs → one ticker or explicit error; never two handleStreamCache loops on that key.
E2e: /stream at metrics=1 and /trusted at default 600, same BOUNCER_KEY_TRAEFIK_TEST, must either fail Traefik plugin init or still apply a cscli ban on /stream within the existing 30s wait. Current compose workaround can stay until this lands, then drop the forced match if fail-on-conflict is chosen.
Out of scope

Plugin fail-closed origins, lock-free processed, parse-once net.IP, range-index origin suffix.
