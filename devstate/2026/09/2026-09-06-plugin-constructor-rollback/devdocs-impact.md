# Devdocs impact
IssueKey: 2026-09-06-plugin-constructor-rollback

## Units reviewed
- knowledge/devdocs/std_go_reclaim.md — consumed during explore; no update required (bindCtx pattern is a plugin.go usage detail, not reclaim API change).

## Findings
None. Constructor rollback and appsec-mode guard are internal to `plugin.go` `New`; existing reclaim usage doc remains accurate.
