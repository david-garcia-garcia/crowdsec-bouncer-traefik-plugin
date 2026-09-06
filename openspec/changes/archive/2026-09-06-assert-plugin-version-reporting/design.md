## Context

See proposal.md Why. LAPI usage-metrics already POSTs `remediation_components[].version` from `Client.pluginVersion` through `crowdsecQuery`, which also sets `User-Agent: Crowdsec-Bouncer-Traefik-Plugin/` + that field. AppSec Query sets the same User-Agent. `plugin.go` `New` already passes `version.go` `pluginVersion` into `lapi.OpenStream` / `OpenLive` and `appsec.Open`. Existing metrics tests inject `pluginVersion: "test"` and never read the field or the header. CrowdSec stamps `cscli bouncers list` from User-Agent `type/version` on API-key requests and also from usage-metrics `BouncerUpdateBaseMetrics`. Bound action is add-tests.

## Goals / Non-Goals

**Goals:**
- Prove the three reporting wires (LAPI JSON version, LAPI User-Agent, AppSec User-Agent) carry the constructed plugin version.
- Prove `New` uses `version.go` without exporting `pluginVersion`.

**Non-Goals:**
- Changing product reporting or release YAML.
- Real CrowdSec / `cscli bouncers list` e2e.
- A file-vs-git-tag static check.

## Decisions

- **Injected distinctive version in package tests, real var at the constructor.** pkg/lapi and pkg/appsec tests cannot import unexported `pluginVersion`. Use `v9.9.9-test` (not `"test"`) so a missed assertion cannot pass by accident. Root-package `New` test compares captured User-Agent to `"Crowdsec-Bouncer-Traefik-Plugin/" + pluginVersion`.
  Alternatives: export `pluginVersion` (product change, out of scope); parse `version.go` from disk in pkg/lapi (wrong owner).
- **One LAPI httptest covers JSON and User-Agent.** `reportMetrics` already POSTs through `crowdsecQuery`. Capture body and `User-Agent` on `/v1/usage-metrics`.
  Alternative: separate decisions-stream User-Agent test — same setter, extra fixture; skip unless the metrics POST is not enough to exercise `crowdsecQuery`.
- **Set `pluginVersion` on the AppSec Client in `query_test.go`.** Same package as `NewTestClient`; do not change that helper’s signature.
  Alternative: add a version argument to `NewTestClient` — extra API for one test.
- **No workflow YAML test.** `release-publish.yml` already fails when the commit message and `version.go` disagree.

## Risks / Trade-offs

- [Root `New` test needs a mock LAPI] → Reuse `plugin_test.go` `liveLAPI` / `cfgLiveAt` and capture `User-Agent` on any LAPI path.
- [AppSec tests currently send empty User-Agent] → Only the new test sets `pluginVersion`; existing tests stay as they are.

## Migration Plan

None. Tests only. Rollback is revert the test files.
