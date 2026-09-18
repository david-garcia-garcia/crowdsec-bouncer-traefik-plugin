## prepare (2026-09-18)
phase: prepare
findings: none
fixed: none
skipped: no research write — existing ext_crowdsec_appsec_protocol answers the wire protocol; this ticket is ValidateParams in-tree

## explore (2026-09-18)
phase: explore
findings: none
fixed: none
skipped: no research write; no new usage packet — validation contract stays on core_plugin_middleware_config-validation

## propose (2026-09-18)
phase: propose
findings: none
fixed: none
skipped: no research write; no new usage packet — fold onto core_plugin_middleware_config-validation

## implement (2026-09-18)
phase: implement
findings: none
fixed: nestif on ValidateParams alone branch — extracted validateAloneCapiAndAppsec
skipped: no research write; no new usage packet; no new spec folder

## codereview (2026-09-18)
phase: codereview
findings: Standards 1 judgement (Duplicated Code: hunt test vs table row)
fixed: none
skipped: Standards 1 judgement — hunt name is the ticket proof and the table row is the spec scenario

## devdocsimpact (2026-09-18)
phase: devdocsimpact
findings: 1 missing-packet (Config validation)
fixed: produced knowledge/devdocs/core_plugin_middleware_config-validation.md
skipped: none

## archive (2026-09-18)
phase: archive
findings: none
fixed: folded core_plugin_middleware_config-validation; moved change to openspec/changes/archive/2026-09-18-alone-mode-appsec-validation/
skipped: Task subagent unavailable (cursor tools: AwaitShell, Delete, EditNotebook, FetchMcpResource, GenerateImage, ReadLints, SwitchMode, TodoWrite, WebFetch, WebSearch); FindSpecHost ran on archive thread

## pullrequest (2026-09-18)
phase: pullrequest
findings: none
fixed: dropped WIP title on PR 80; waited CI success on 4e18715 (Main 35361106893, E2E 35361106925)
skipped: no comments.md replies
