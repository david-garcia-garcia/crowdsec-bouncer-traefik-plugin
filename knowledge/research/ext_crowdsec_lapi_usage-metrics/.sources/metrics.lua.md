---
url: https://github.com/crowdsecurity/lua-cs-bouncer/blob/59f3521e3918377fc1eb97d59a4056b6e9f5782f/lib/plugins/crowdsec/metrics.lua
title: lua-cs-bouncer usage-metrics JSON
fetched: 2026-09-05
authority: source
ref: github.com/crowdsecurity/lua-cs-bouncer@59f3521e3918377fc1eb97d59a4056b6e9f5782f:lib/plugins/crowdsec/metrics.lua
---

Envelope: version=userAgent, os.name/version from osinfo, type=lua-bouncer, name="nginx bouncer", utc_startup_timestamp, feature_flags forced to JSON [].
metrics is an array of one {items, meta{utc_now_timestamp, window_size_seconds}}.
Item unit: ip for active_decisions, else request. POST /v1/usage-metrics. Also encodes log_processors=null.
Empty feature_flags rewritten from {} to [] for vanilla lua-cjson (LAPI 400 otherwise).
