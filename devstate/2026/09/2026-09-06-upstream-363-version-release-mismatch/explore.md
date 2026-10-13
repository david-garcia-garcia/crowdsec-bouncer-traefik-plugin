# Explore
IssueKey: 2026-09-06-upstream-363-version-release-mismatch

## Concepts

```
  version.go pluginVersion ("v1.7.1")
            │
            ▼
  plugin.go New  ──► lapi.OpenStream / OpenLive(pluginVersion)
            │        appsec.Open(pluginVersion)
            │
            ▼
  lapi.Client.pluginVersion ──► POST /v1/usage-metrics
                                remediation_components[].version
                            ──► User-Agent Crowdsec-Bouncer-Traefik-Plugin/<version>
                                (crowdsecQuery: decisions, stream, metrics)

  appsec.Client.pluginVersion ──► User-Agent Crowdsec-Bouncer-Traefik-Plugin/<version>
```

`cscli bouncers list` shows the LAPI **bouncer row** `version`. CrowdSec stamps that row from `User-Agent` `type/version` on API-key requests; usage-metrics `BouncerUpdateBaseMetrics` also writes `version` from the JSON envelope. Both wires must carry `pluginVersion`. Owner: `knowledge/research/ext_crowdsec_lapi_usage-metrics` (`api_key.go`, `bouncers.go`).

`core_plugin_lapi_usage-metrics` already SHALLs envelope `version` from the plugin version and User-Agent `Crowdsec-Bouncer-Traefik-Plugin/<version>`. Tests do not assert those fields.

Upstream #322 and #363 are the same failure: tag published while `pluginVersion` still named the previous release. Traefik caches the tagged archive, so a post-tag bump never reaches users. This fork’s release-prepare/publish workflows bump `version.go` before the tag. Bound action is `add-tests`, not a new release or workflow rewrite.

## Current (measured)

- `version.go` reads `v1.7.1`. Runtime stale-tag symptom **not reproduced** on this tree.
- `pkg/lapi/metrics_test.go` injects `pluginVersion: "test"` and never reads `usageComponent()["version"]` or the request `User-Agent`.
- No `*_test.go` matches `User-Agent` or `Crowdsec-Bouncer-Traefik-Plugin`.
- `pkg/appsec/test_client.go` `NewTestClient` leaves `pluginVersion` empty (existing Query tests do not cover the version header).
- `plugin_test.go` `liveLAPI` / `New` already drives LAPI HTTP; it does not capture `User-Agent`.
- Devdocs usage (`core_plugin_middleware`, `core_plugin_lapi_usage-metrics`) already says pass `pluginVersion` from `version.go`. No Language gap. No new research write.

## Decisions

Prove we do **not** have the upstream problem. Do not change product reporting. Do not export `pluginVersion`. Do not edit release YAML unless a test cannot be honest without it (it can).

Test shape (three httptest seams, one PR covering #322 and #363):

1. **LAPI envelope + User-Agent** — in `pkg/lapi`, distinctive injected version (not `"test"`). `reportMetrics` already POSTs through `crowdsecQuery`, so one httptest can assert `remediation_components[0].version` **and** `User-Agent: Crowdsec-Bouncer-Traefik-Plugin/<injected>`.
2. **AppSec User-Agent** — Query httptest with `pluginVersion` set on the Client (field assign in the test, or a one-line `NewTestClient` version argument only if the test cannot set the field). Assert the same User-Agent prefix. Do not change Query behavior.
3. **`version.go` wiring** — root-package test: `New` against a mock LAPI captures User-Agent and asserts it equals `Crowdsec-Bouncer-Traefik-Plugin/` + `pluginVersion` (the unexported var). That is the string `plugin.go` passes today. Do not hardcode `v1.7.1` in the assertion.

Skip: real `cscli bouncers list` e2e; file-vs-git-tag static check (no tag in unit tests; `release-publish.yml` already fails when commit message and `version.go` disagree); exporting `pluginVersion`; bumping the version.

## Open questions

- Q: Which seam proves `version.go` is what LAPI/cscli would record, without exporting `pluginVersion`?
  Decision: assumed — pkg/lapi httptest with an injected distinctive version proves the Client copies version into JSON and User-Agent; a root-package `New` test asserts that User-Agent uses the unexported `pluginVersion` from `version.go`. AppSec Query httptest covers the sibling User-Agent. Do not export the var.
  By: explore

- Q: Does a static `version.go` vs git-tag or workflow-YAML test add value?
  Decision: assumed — no. Unit tests have no release tag. `release-publish.yml` already exits 1 when commit message and `version.go` disagree. Bound is add-tests, not workflow edits.
  By: explore

- Q: Should `NewTestClient` grow a version argument?
  Decision: assumed — set `pluginVersion` on the Client in the new AppSec test. Change `NewTestClient` only if the field cannot be set from `query_test.go` (same package: it can).
  By: explore
