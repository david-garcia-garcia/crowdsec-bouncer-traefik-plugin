---
ref: github.com/crowdsecurity/lua-cs-bouncer@59f3521e3918377fc1eb97d59a4056b6e9f5782f:t/19_appsec_drop_unreadable_body_get.t
title: GET not dropped when drop enabled
fetched: 2026-09-06
authority: source
---

TEST 1: APPSEC_DROP_UNREADABLE_BODY=true does not drop GET requests (no body expected).

HTTP/2 simulated; GET still reaches AppSec mock.
