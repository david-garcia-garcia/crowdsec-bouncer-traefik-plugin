---
url: https://github.com/crowdsecurity/crowdsec/blob/cc76dbbce40bd2e6a3ce1ba07e3c41d8b462de66/pkg/appsec/waf_helpers.go
title: pkg/appsec/waf_helpers.go GrantChallengeCookie variants
fetched: 2026-09-05
authority: source
ref: github.com/crowdsecurity/crowdsec@cc76dbbce40bd2e6a3ce1ba07e3c41d8b462de66:pkg/appsec/waf_helpers.go
---

Expr helper GrantChallengeCookie in pre_eval/post_eval calls GrantChallengeCookie (307 redirect).

Same helper name in on_challenge_submit calls GrantAllowlistCookieInline: attach cookie to existing submit JSON; a 307 would break the client JS state machine. Both halt later rules.

ExemptFromChallenge is in the pre_eval/post_eval/on_match env.
