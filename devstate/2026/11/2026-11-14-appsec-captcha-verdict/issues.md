# Issues

- [ ] note large  `knowledge/debt/2026-11-14-lifecycle-e2e-flaky-timeouts.md`
  Why: the lifecycle Pester job failed twice and passed once on unchanged product code, on ~20 s timeouts in LAPI-only tests.
- [ ] note large  `knowledge/debt/2026-11-14-captcha-redirect-same-origin-path.md`
  Why: captcha redirects echo the request URL as Location, so a `//host` path can redirect off-site; this change widens who reaches that sink.
