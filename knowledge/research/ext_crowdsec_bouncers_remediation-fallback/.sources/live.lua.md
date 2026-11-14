---
url: https://github.com/crowdsecurity/lua-cs-bouncer/blob/4aad1dfa653d9d96fb5c0114ae930eb2353214c8/lib/plugins/crowdsec/live.lua
title: lua-cs-bouncer live processing
fetched: 2026-11-14
authority: source
ref: github.com/crowdsecurity/lua-cs-bouncer@4aad1dfa653d9d96fb5c0114ae930eb2353214c8:lib/plugins/crowdsec/live.lua
---

live_query_process caches "<type>/<origin>" for the first decision of GET /v1/decisions?ip=, then L130: if bouncing_on_type == decision.type or bouncing_on_type == "all" return false (block) with decision.type; else return true (allowed).
