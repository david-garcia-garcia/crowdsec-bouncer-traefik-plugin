## 1. Estimator

- [ ] 1.1 Add `EstimatedSize() int64` on `clientrequest.Request` plus the 50 MiB ContentLength constant in `pkg/clientrequest`; sum RequestURI, Host, Header keys/values, and capped ContentLength; do not read Body
- [ ] 1.2 Tests in `pkg/clientrequest` for named fields, ContentLength cap, ContentLength `-1`, nil embed, and that Body is not read

## 2. Byte window

- [ ] 2.1 Add `IncDroppedBytes` (Client thin-forward + reporter) writing `dropped` / `byte` with `origin` + `ip_type` only; saturate those keys in add and restore; leave `IncDropped` and request/processed wrap unchanged
- [ ] 2.2 Tests in `pkg/lapi/zzz_metrics_test.go` for both series on one drop, omitted `remediation` on the byte item, saturate-on-add, saturate-on-failed-POST restore; existing unit `request` cases stay

## 3. Drop recording

- [ ] 3.1 Change `recordDropped` to `(req, origin, remediation)` and have it call `IncDropped` then `IncDroppedBytes(req.EstimatedSize())`; update ban, unsolved captcha, and AppSec envelope call sites
- [ ] 3.2 Keep `TestDroppedCount` keyed on unit `request`; add coverage that a remediating path also records the byte series

## 4. Proof and usage

- [ ] 4.1 Keep e2e `-Unit request` cases; add a `dropped` / `byte` assertion in `tests/e2e/real/usage_metrics.Tests.ps1`
- [ ] 4.2 Update `knowledge/devdocs/core_plugin_lapi_usage-metrics.md` How to use / snippet / gotchas for the byte series; do not rename the file
- [ ] 4.3 Run `go test ./pkg/clientrequest/... ./pkg/lapi/... ./pkg/bouncer/...`
