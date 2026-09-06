# Standards

1. [hard] Leave a trail — `pkg/captcha/captcha.go:137` — `Check` now has two logical blocks (read session token from the request, then cache lookup for grace) but neither block has a one-line intro; the method comment covers the whole job, not the split paths
   → Add block intros before the empty-token early return and before the cache Get, matching the intro on the valid-solve branch in `ServeHTTP`
   Status: done
   Argument: block intros on token read and cache Get (codereview).

2. [hard] Leave a trail — `pkg/captcha/captcha.go:164` — new `sessionTokenFromRequest` has four logical blocks (nil guard, cookie read, length check, hex decode) with no block intros despite a multi-step validation body
   → Add one-line comments introducing each block (nil request, read `crowdsec_captcha`, reject wrong length, reject non-hex)
   Status: done
   Argument: block intros on nil, cookie read, length, and hex (codereview).

3. [judgement] Mysterious Name — `pkg/captcha/captcha_test.go:86` — local `session` holds the issued `*http.Cookie`; the name does not say cookie and reads like generic session state in a test already about captcha sessions
   → Rename to `sessionCookie` (or `captchaCookie`)
   Status: skipped
   Argument: judgement; the local is the cookie pulled from Set-Cookie in a test already about the session cookie.
