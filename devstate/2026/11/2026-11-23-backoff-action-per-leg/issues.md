# Issues

- [ ] note large  `knowledge/debt/2026-11-23-waf-failure-captcha-downgrade-reason.md`
  Why: an AppSec or ModSec failure-action captcha that downgrades to a ban shows ban-template reason `LAPI`, because `handleRemediationServeHTTP` hard-codes `ReasonLAPI`.
