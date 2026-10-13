---
url: https://github.com/crowdsecurity/lua-cs-bouncer/blob/59f3521e3918377fc1eb97d59a4056b6e9f5782f/lib/crowdsec.lua
title: lua dropped/processed labels
fetched: 2026-09-05
authority: source
ref: github.com/crowdsecurity/lua-cs-bouncer@59f3521e3918377fc1eb97d59a4056b6e9f5782f:lib/crowdsec.lua
---

metrics:increment("processed", 1, {ip_type=ip_version}).
dropped increments with {ip_type, origin} only. Remediation type is returned separately; it is not a metrics label.
