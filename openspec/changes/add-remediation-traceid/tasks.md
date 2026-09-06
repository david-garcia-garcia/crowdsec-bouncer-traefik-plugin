## 1. Config

- [ ] 1.1 Add `RemediationTraceIDCustomName` to `Config`, `New` default `""`, json `remediationTraceIdCustomName`
- [ ] 1.2 Document the key in README next to `TraceHeadersCustomName` (empty = off; response header on ban and captcha HTML)

## 2. Ban path

- [ ] 2.1 Wire the knob on `Bouncer`; generate 16 lowercase hex (`crypto/rand`) when the knob is set
- [ ] 2.2 Set the response header before `WriteHeader` on ban (including HEAD); put the same value in template `TraceID`; skip incoming passthrough when the built-in knob is set
- [ ] 2.3 On rand failure, log warn, omit header/`TraceID`, still serve the ban page
- [ ] 2.4 Unit tests: header+body match; HEAD has header and empty body; passthrough when built-in empty; built-in wins when both set; rand failure still 403

## 3. Captcha path

- [ ] 3.1 Pass the generated ID into `captcha.ServeHTTP`; captcha sets the header and `{{ .TraceID }}` on HTML only (not solved-captcha 302)
- [ ] 3.2 Unit tests: captcha HTML header+template; solved redirect has no built-in trace header

## 4. Mock e2e

- [ ] 4.1 `custom-ban-page`: assert generated 16-hex header and body when the new knob is set (keep existing incoming `X-Trace` scenario or split)
- [ ] 4.2 `captcha`: assert generated header and template TraceID on the captcha page
