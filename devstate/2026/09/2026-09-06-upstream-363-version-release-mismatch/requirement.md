# Requirement
IssueKey: 2026-09-06-upstream-363-version-release-mismatch

## Problem
Upstream releases v1.6.0 and v1.7.0 were tagged while `pluginVersion` in source still read the prior release, so `cscli bouncers list` showed a stale version (same failure mode for #322 and #363). This fork’s `master` already bumps `version.go` before tagging via release workflows, but nothing tests that LAPI usage metrics and HTTP User-Agent report the configured version or guards against a future manual release bypass.

## Current (code)
- `version.go:5` — `pluginVersion = "v1.7.1"` (matches current tree; upstream symptom not present on master).
- `plugin.go:55-72` — passes `pluginVersion` into `lapi.OpenStream`, `lapi.OpenLive`, and `appsec.Open`.
- `pkg/lapi/client.go:114-155` — stores `pluginVersion` on `Client`.
- `pkg/lapi/client_metrics.go:179-181` — usage POST sends `remediation_components[].version` = `c.pluginVersion` (what LAPI/cscli records).
- `pkg/lapi/client_http.go:86` — LAPI requests set `User-Agent: Crowdsec-Bouncer-Traefik-Plugin/` + `c.pluginVersion`.
- `pkg/appsec/query.go:139` — AppSec requests set the same User-Agent prefix + `c.pluginVersion`.
- `.github/workflows/release-prepare.yml:3-9,51-60` — bumps `version.go` before tag; cites #322/#363.
- `.github/workflows/release-publish.yml:6-8,34-35` — fails publish if commit message version and `version.go` disagree.
- `pkg/lapi/metrics_test.go:140,178-182` — metrics tests use hardcoded `pluginVersion: "test"`; `usageComponent` helper does not assert `version` field.
- `not found` — unit or e2e test asserting usage-metrics `version` matches `pluginVersion` passed from `plugin.go`.
- `not found` — unit test asserting LAPI/AppSec User-Agent includes the passed `pluginVersion`.
- `not found` — test or CI guard that `version.go` `pluginVersion` would fail release-publish mismatch check.

## Desired
- Add tests proving `pluginVersion` from `version.go` flows into LAPI usage metrics `remediation_components[].version` and into LAPI/AppSec `User-Agent` headers (httptest or existing test harness).
- Optionally assert release workflow invariant (version.go vs tag) in a lightweight test or workflow-adjacent check — only if honest without changing product behavior.
- Do not change runtime version reporting unless a test cannot be honest without a one-line fix.

## Affected
- `version.go` (read-only reference in tests)
- `pkg/lapi/metrics_test.go` and/or new `pkg/lapi/*_test.go`
- `pkg/appsec/*_test.go` (User-Agent path)
- Possibly `.github/workflows/` (only if test coverage requires documenting existing guard)

## Out of scope
- Bumping `pluginVersion` for a new release (release-prepare workflow owns that).
- Changing Traefik plugin cache behavior or upstream tag policy.
- Broad e2e with real CrowdSec + `cscli bouncers list` (unit/httptest sufficient per assessment).
- Refactoring LAPI client construction or metrics schema beyond version field assertions.

## Unknowns
- Whether to test via exported `pluginVersion` variable, a test helper, or inject version only through `lapi.New` / `appsec.New` (explore decides seam).
- Whether a static test reading `version.go` on disk adds value vs runtime httptest assertions only.

## Tensions
- Symptom is `present-fixed-unproven` on master — tests prove we keep the fix, not reproduce upstream stale tags in production.
- Assessment cites release workflows as mitigation; ticket bound is `add-tests`, not workflow changes — workflow edits only if tests cannot cover the invariant otherwise.
- #322 and #363 share one failure mode; one PR must cover both without duplicating two tickets.
