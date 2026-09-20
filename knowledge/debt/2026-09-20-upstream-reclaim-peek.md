# Upstream exact Peek and stop CI from restoring published reclaim

IssueKey: 2026-09-20-lapi-session-exclusive
Size: large
Action: note

## Why this follow-up

This change ships an ad-hoc `Peek(key) (any, State, bool)` on vendored `traefik-middleware-utilities/reclaim/table.go` and re-exports it from `pkg/reclaim`. Published utilities at this plugin’s pin (`v1.0.6`) still have no Peek. Main Process `go mod vendor` restores that published tree and makes `Default().Peek` fail typecheck. This change comments that vendor step out so CI typechecks the committed vendor Peek. A later uncomment, a catalog/Yaegi load that does not use this `vendor/`, or a pin bump that restores the published tree, drops Peek and exclusive-name detection cannot compile.

## Why it was not taken

The ticket requires shipping Peek in this change and parking restore/upstream as follow-up. Human will upstream later. Unattended take is only small rows on files this run created; this is a third-party module plus CI workflow.

## Risks

A `go mod vendor` that restores published reclaim removes Peek and exclusive LAPI session ownership fails to build. Catalog installs without this vendor tree never see Peek. Two Traefik middleware names can share one CrowdSec stream cursor again if the patch is lost and the call site is reverted.

## Context

Workaround this change ships: exact Peek on `vendor/github.com/david-garcia-garcia/traefik-middleware-utilities/reclaim/table.go` plus `pkg/reclaim` re-export, and Main Process skips `go mod vendor` so lint uses that committed tree. No `PeekLivePrefix`. No fork of the whole table into `pkg/reclaim`. Upstream: add Peek to `github.com/david-garcia-garcia/traefik-middleware-utilities/reclaim`, bump the pin, then drop the vendor-only method. CI: re-enable `go mod vendor` and vendor git-diff only after the published module includes Peek.
