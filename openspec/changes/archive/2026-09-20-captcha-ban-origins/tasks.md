## 1. Config and Client residue

- [x] 1.1 Add `BanToCaptchaOrigins []string` to Config with empty default
- [x] 1.2 Copy trimmed non-empty entries onto `lapi.Client` in `New` (not on the Open key)

## 2. Remediation mapping

- [x] 2.1 Add `remediationKindForOrigin` / listed-origin match (`lists` prefix vs `lists:<name>`, exact otherwise)
- [x] 2.2 Use the helper in `streamPutItem`, stream Range upsert, and `queryLiveDecisions`
- [x] 2.3 Live strongest pick uses remapped kind (still-ban wins)

## 3. Tests and docs

- [x] 3.1 Unit tests for match rules, empty default, unlisted ban, captcha type, live strongest pick
- [x] 3.2 Mock LAPI origin/scenario (default origin `crowdsec`); e2e scenario `captcha-ban-origins`
- [x] 3.3 README `BanToCaptchaOrigins` (cite upstream PR 369 and per-list matching)

## 4. Verification

- [x] 4.1 `go test ./pkg/lapi/... ./pkg/configuration/...`
