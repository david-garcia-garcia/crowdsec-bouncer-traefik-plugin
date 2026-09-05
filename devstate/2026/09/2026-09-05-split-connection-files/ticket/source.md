# Split CrowdsecConnection files

Highest-leverage physical isolation: split `pkg/crowdsecconnection/connection.go` into the files named above. Evidence: connection.go is the god file (600+ lines) packing seven jobs. Desired: one job per file, CrowdsecConnection type unchanged, tests still pass.

FILE SPLIT only inside `pkg/crowdsecconnection/`. `connection.go` still owns stream, live lookup, AppSec, metrics, CAPI login, and LAPI HTTP. `identity.go` and `connection_decisions.go` already show the pattern. Finish with:

- connection_appsec.go
- connection_stream.go
- connection_live.go
- connection_http.go
- connection_metrics.go

Keep the same package. Same exported API. No new packages (`pkg/appsec` is out of scope). No behavior change. Do not move GetTLSConfigCrowdsec (sibling ticket). Do not change identity, DecisionScopeHeaders, cache constants, pkg/ip, configuration.go layout, or Prepare/plugin mutation.

Sibling tickets that MUST NOT be taken: 2026-09-05-split-configuration-files, 2026-09-05-split-ip-trust, 2026-09-05-scope-headers-identity, 2026-09-05-remediation-codes-owner, 2026-09-05-decisionscope-mode-bool, 2026-09-05-config-prepare-snapshot.
