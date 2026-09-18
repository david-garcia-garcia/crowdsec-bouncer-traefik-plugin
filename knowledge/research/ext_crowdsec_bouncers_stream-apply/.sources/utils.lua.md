---
url: https://github.com/crowdsecurity/lua-cs-bouncer/blob/ec94d512927cf70be865686e4eb928d128189633/lib/plugins/crowdsec/utils.lua
title: lua-cs-bouncer item_to_string
fetched: 2026-09-18
authority: source
ref: github.com/crowdsecurity/lua-cs-bouncer@ec94d512927cf70be865686e4eb928d128189633:lib/plugins/crowdsec/utils.lua
---

item_to_string(item, scope): scope ip uses the item as the address; scope range splits the CIDR. Other scopes return nil,nil (skipped).
Key is ipv4_<netmask>_<network_address> or ipv6_<netmask>_<uint32s>. Bare IP defaults cidr 32 / 128.
Deleted and new use this same helper, so the same IP or the same CIDR share one cache key. Decision id is not part of the key.
