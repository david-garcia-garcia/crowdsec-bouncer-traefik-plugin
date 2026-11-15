# Issues

- [ ] note large  `knowledge/debt/2026-11-15-ban-captcha-path-rules-ambiguous-path-evasion.md`
  Why: ban and captcha path rules still match the decoded path, so an ambiguous path the backend resolves into their prefix (for example `/x/..;/admin` vs `^/admin`) evades them.
