Do NOT remove Redis. Dropped PR #59 (remove-redis-cache) because the operator still wants a choice of store. Fix the stream-sharing bug instead.

CrowdSec LAPI stream cursor is per hashed X-Api-Key + outbound IP (pod IP), not per API key. Evidence: knowledge/research/ext_crowdsec_lapi_stream-cursor/ and https://github.com/crowdsecurity/crowdsec/issues/3726. Today CachePrefix for stream/alone is SessionHex (LAPI URL+key only) and handleStreamCache skips LAPI when key "updated" exists, so two pods with redisCacheEnabled share one dump and one lease — wrong.

Desired:
- Operator chooses where THIS instance stores decisions: in-memory map vs Redis. The existing redisCacheEnabled (and host/password/db knobs) IS that storage choice if it already exists; keep it. If analysis finds there is no clear storage knob, add one. Do not invent a second parallel enable flag beside a working redisCacheEnabled.
- Redis MUST NOT mean shared stream across bouncer instances/pods. Each instance has its own Redis key prefix so remediations, range-index, and the "updated" lease are private to that instance. Each pod keeps polling its own LAPI stream.
- Prefix uniqueness: default to an instance identity the process already has (hostname is acceptable) plus the existing LAPI session hex; add an optional explicit config knob (e.g. redisCacheInstanceId or similar, name for the scope) so Kubernetes can set the pod name. Empty knob → hostname (or documented fallback). Same instance + same LAPI session → same keys (in-process warn-and-wire still shares one Client / one prefix). Different hosts/pods → different prefixes.
- Write why in spec/devdocs: LAPI stream = key+IP; Redis is a local durable/off-heap store, not a cross-replica stream bus.
- Keep SimpleRedis, Dragonfly e2e, captcha HMAC cookie, in-process reclaim/warn-and-wire.
Out of scope: deleting Redis; changing CrowdSec LAPI identity; captcha redesign; AppSec.
