## 1. Regression tests

- [ ] 1.1 Add pkg/lapi tests that fail on master if streamPutItem skips type challenge or allow
- [ ] 1.2 Add tests that fail on master if strongestLiveDecision ignores unknown types or lets captcha outrank them
- [ ] 1.3 Add tests that fail on master if queryLiveDecisions/LiveLookup allows a challenge-only list, and that an empty list stays no-remediation
- [ ] 1.4 Add a stream Range test that fails on master if type allow is skipped
- [ ] 1.5 Add a TRACE test that handleStreamCache:unknownType is Trace, not Info or Debug
- [ ] 1.6 Keep TestRemediationValue asserting empty for allow

## 2. LAPI ingest

- [ ] 2.1 Add a pkg/lapi helper that maps ban/captcha via RemediationValue and unknown types to BannedValue, TRACE-logging stem handleStreamCache:unknownType via logger.Trace
- [ ] 2.2 Call the helper from streamPutItem, Range upsert, strongestLiveDecision, and queryLiveDecisions
- [ ] 2.3 Do not change RemediationValue

## 3. Usage docs

- [ ] 3.1 Update knowledge/devdocs/core_plugin_lapi_stream-apply.md so unknown types store as ban
- [ ] 3.2 Update knowledge/devdocs/core_plugin_lapi_origin-based-decision-remap.md so ingest fail-closed is ban and RemediationValue stays empty

## 4. Verify

- [ ] 4.1 Run go test ./pkg/lapi ./pkg/decisionscope on this machine
