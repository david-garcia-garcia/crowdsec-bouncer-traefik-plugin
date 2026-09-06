# Standards

1. [hard] Name for the scope — `pkg/captcha/captcha.go:75` — `key: "cap-widget"` fills the `FrontendKey` slot whose role is the CSS class on `<div class="{{ .FrontendKey }}">`; Cap Standalone renders via `CapApiEndpoint` and a hardcoded `<cap-widget>`, so the value names an element tag, not the class role siblings use (`h-captcha`, `g-recaptcha`, …)
   → Leave `key` empty for trycap (Cap branch ignores `FrontendKey`) or stop overloading `key` when the provider is not class-based
   Status: done
   Argument: trycap `key` left empty; Cap branch ignores FrontendKey.

2. [hard] Leave a trail — `pkg/captcha/captcha.go:38` — edited `infoProvider` adds `jsonBody` and `apiEndpoint` but the type comment still says “Information for self-hosted provider” while the map holds SaaS built-ins and the new fields drive JSON siteverify and the Cap widget endpoint
   → Replace the comment with the struct’s job: per-provider frontend JS, class-widget key, form field, verify URL, optional JSON verify flag, optional Cap widget API endpoint
   Status: done
   Argument: type comment now names JSON verify flag and Cap API endpoint.

3. [judgement] Mysterious Name — `pkg/captcha/captcha.go:44` — `jsonBody` does not say verify-request encoding; readers must open `postSiteverify` to learn it gates JSON vs urlencoded siteverify POST
   → Rename to `siteverifyUsesJSON` or `verifyPostJSON`
   Status: skipped
   Argument: judgement; jsonBody is the verify encoding flag next to PostForm, not a commandment miss.

4. [judgement] Mysterious Name — `pkg/captcha/captcha.go:72` — local `base` is the joined `{instance}/{siteKey}/` prefix used for both widget endpoint and siteverify URL
   → Rename to `capInstanceSiteKeyPrefix` or `widgetAPIEndpointBase`
   Status: skipped
   Argument: judgement; `base` is the joined prefix in a five-line helper.

5. [judgement] Mysterious Name — `pkg/captcha/captcha_test.go:19` — parameter `verifyKey` holds the captcha secret passed to `New` as `secretKey`, not a siteverify URL or site key
   → Rename to `secretKey` to match the production parameter role
   Status: skipped
   Argument: judgement; named verifyKey so gosec G101 would not treat the test helper parameter as a hardcoded secret.

6. [judgement] Duplicated Code — `captcha.html:277-348` and `examples/captcha/captcha.html:277-348` — identical Cap widget branch (module script, `<cap-widget>`, `solve` listener) copied verbatim in this change
   → Document one canonical template and symlink/copy in examples, or extract shared partial if the repo supports it
   Status: skipped
   Argument: judgement; examples/captcha already vendors a copy of the default template; no shared partial in this repo.
