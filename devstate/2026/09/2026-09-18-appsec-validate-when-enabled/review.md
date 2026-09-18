## prepare (2026-09-18)
phase: prepare
findings: none
fixed: none
skipped: no Task subagent used; prepare wrote the bus in-process

## explore (2026-09-18)
phase: explore
findings: none
fixed: none
skipped: no Task subagent used; no research write (AppSec protocol and Traefik New already covered); no usage write (enabled gate is not dest yet)

## propose (2026-09-18)
phase: propose
findings: none
fixed: none
skipped: no Task subagent used; no research write; no usage write (enabled gate is not dest yet; deferred to devdocs-impact)

## implement (2026-09-18)
phase: implement
findings: none
fixed: gated validateAppsecURLKeyAndTLS on CrowdsecAppsecEnabled in every mode; dropped validateLapiAndAppsecConnection; flipped leftover-CA dest test; added alone/live on-fail and off-leftover cases
skipped: no Task subagent used; no new spec folder; usage packet deferred to devdocs-impact; no comments.md FIX rows

## codereview (2026-09-18)
phase: codereview
findings: none
fixed: none
skipped: Task unavailable to nested executor (cursor namespace has no Task); six axis files written in-process from checklists; no hard/missing/wrong to apply

## devdocsimpact (2026-09-18)
phase: devdocsimpact
findings: 1 stale-usage (Config validation)
fixed: produced enabled-gate Language + usage on core_plugin_middleware_config-validation.md
skipped: none

## archive (2026-09-18)
phase: archive
findings: none
fixed: folded core_plugin_middleware_config-validation into catalog; moved change to openspec/changes/archive/2026-09-18-appsec-validate-when-enabled/
skipped: Task unavailable in archive subagent; FindSpecHost ran on this thread

## pullrequest (2026-09-18)
phase: pullrequest
findings: none
fixed: reused OPEN PR #97; ready title; waited CI on f0ea972 (four checks success)
skipped: no comments.md; no second PR; gh not on PATH — used GitHub MCP check runs
