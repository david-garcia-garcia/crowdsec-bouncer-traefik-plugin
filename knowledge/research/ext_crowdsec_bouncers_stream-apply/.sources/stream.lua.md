---
url: https://github.com/crowdsecurity/lua-cs-bouncer/blob/ec94d512927cf70be865686e4eb928d128189633/lib/plugins/crowdsec/stream.lua
title: lua-cs-bouncer stream_query_process
fetched: 2026-09-18
authority: source
ref: github.com/crowdsecurity/lua-cs-bouncer@ec94d512927cf70be865686e4eb928d128189633:lib/plugins/crowdsec/stream.lua
---

stream:stream_query_process decodes the LAPI JSON body then applies arrays in this order:
1. Comment "-- process deleted decisions". If decisions.deleted is a table, for each decision: item_to_string(value, scope) → key; self:delete(key) removes decision_cache/<key>. Captcha type also deletes captcha_<value>.
2. Comment "-- process new decisions". If decisions.new is a table, for each decision matching bouncing_on_type (or "all"): parse duration TTL, item_to_string(value, scope) → key, self:set(key, type/origin/ip_type, ttl).

self:set writes ngx.shared.crowdsec_cache key "decision_cache/" .. key. self:delete removes that same prefix+key.
Same scope+value in both arrays: delete then set. Replacement remains.
