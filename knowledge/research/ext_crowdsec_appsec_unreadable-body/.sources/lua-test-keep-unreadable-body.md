---
ref: github.com/crowdsecurity/lua-cs-bouncer@59f3521e3918377fc1eb97d59a4056b6e9f5782f:t/20_appsec_keep_unreadable_body.t
title: APPSEC_DROP_UNREADABLE_BODY=false forwards to AppSec
fetched: 2026-09-06
authority: source
---

TEST 1: APPSEC_DROP_UNREADABLE_BODY=false (default) lets a POST with unreadable body reach AppSec.

Simulates HTTP/2 with no content-length. AppSec mock on 7422 must be reached (returns 200 allow).
