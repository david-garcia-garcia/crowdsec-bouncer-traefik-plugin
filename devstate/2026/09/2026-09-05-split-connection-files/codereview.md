# Code review
Pin: origin/master (2d4acf366cf91884967f91e87a54e7744d62078d)...HEAD
Diff: `git diff origin/master...HEAD -- . ':!devstate' ':!.cursor'`
Commits: d946538 docs(openspec): propose split-connection-files; 7d82094 refactor(crowdsecconnection): split connection.go into job files

Gotchas pasted:
- core_plugin_middleware.md: do not put middleware name in reclaim key; Close stops tickers; do not use sync.Once
- core_plugin_appsec.md: AppsecQuery captcha failure is ErrFailureCaptcha
- core_plugin_decisionscope.md: do not geolocate; lease hit still hydrates range-index

## Standards
none

## Spec
none

## Security
none

## Performance
none

## Dead
none

Standards: 0 findings, worst: none
Spec: 0 findings, worst: none
Security: 0 findings, worst: none
Performance: 0 findings, worst: none
Dead: 0 findings, worst: none

## Applied
none.

## Recorded and skipped
none.
