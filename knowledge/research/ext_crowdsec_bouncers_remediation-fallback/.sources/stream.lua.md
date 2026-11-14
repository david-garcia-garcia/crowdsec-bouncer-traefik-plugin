---
url: https://github.com/crowdsecurity/lua-cs-bouncer/blob/4aad1dfa653d9d96fb5c0114ae930eb2353214c8/lib/plugins/crowdsec/stream.lua
title: lua-cs-bouncer stream processing
fetched: 2026-11-14
authority: source
ref: github.com/crowdsecurity/lua-cs-bouncer@4aad1dfa653d9d96fb5c0114ae930eb2353214c8:lib/plugins/crowdsec/stream.lua
---

L238 "-- process deleted decisions": for every decision in decisions.deleted, key = item_to_string(value, scope); self:delete(key). No type check. L253: if decision.type == "captcha" also delete "captcha_<value>" state.

L273 "-- process new decisions": L279 if bouncing_on_type == decision.type or bouncing_on_type == "all" then store "<type>/<origin>/<ip_type>" under decision_cache/<key> with the decision TTL. Other types are not stored.
