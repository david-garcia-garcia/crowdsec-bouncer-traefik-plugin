---
url: https://github.com/crowdsecurity/lua-cs-bouncer/blob/4aad1dfa653d9d96fb5c0114ae930eb2353214c8/lib/plugins/crowdsec/config.lua
title: lua-cs-bouncer config loader
fetched: 2026-11-14
authority: source
ref: github.com/crowdsecurity/lua-cs-bouncer@4aad1dfa653d9d96fb5c0114ae930eb2353214c8:lib/plugins/crowdsec/config.lua
---

L6: valid_bouncing_on_type_values = {'ban', 'captcha', 'all'}.
L14: default_values BOUNCING_ON_TYPE = "ban". default_values (L8-37) has no FALLBACK_REMEDIATION entry.
L103-107: invalid BOUNCING_ON_TYPE -> log "unsupported value ... Using default value 'ban' instead".
L128-131: FALLBACK_REMEDIATION must be one of {'captcha', 'ban'}; otherwise log "unsupported value '<v>' for variable 'FALLBACK_REMEDIATION'. Using default value 'ban' instead" and value = "ban". No "ignore"/"passthrough" value.
