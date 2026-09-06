---
ref: github.com/crowdsecurity/lua-cs-bouncer@59f3521e3918377fc1eb97d59a4056b6e9f5782f:t/18_appsec_drop_unreadable_body.t
title: APPSEC_DROP_UNREADABLE_BODY=true bans POST
fetched: 2026-09-06
authority: source
---

TEST 1: APPSEC_DROP_UNREADABLE_BODY=true bans a POST whose body is unreadable.

AppSec mock logs "should not be reached when dropping unreadable body".

Simulates HTTP/2+ via ngx.req.http_version = function() return 2.0 end
