# Assessment: upstream#388

- relevant: yes
- kind: feature
- affected: yes
- status: present-unfixed
- proof: none
- recommended-action: fix
- slug: 2026-09-06-upstream-388-split-appsec-timeout
- rationale: Our fork split LAPI and AppSec into separate packages but still exposes a single `HTTPTimeoutSeconds` in `pkg/configuration/configuration.go` (default 10). That value is wired into `http.Client.Timeout` for LAPI stream/live pulls (`pkg/lapi/client.go`), per-request AppSec queries (`pkg/appsec/client.go`), and captcha siteverify (`pkg/bouncer/bouncer.go`), all multiplied by `time.Second`. AppSec reclaim identity in `pkg/appsec/session.go` also hashes the shared field. There is no `AppsecTimeoutSeconds` (or equivalent), no millisecond granularity, and no unit or e2e test that AppSec can use a tighter timeout than LAPI while fail-open still works.

## Evidence
- current: pkg/configuration/configuration.go, pkg/lapi/client.go, pkg/appsec/client.go, pkg/appsec/session.go, pkg/bouncer/bouncer.go
- tests: none
