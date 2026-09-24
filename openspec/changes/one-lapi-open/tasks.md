## 1. Unify lapi.Open

- [ ] 1.1 In `pkg/lapi/session.go`, replace `OpenStream` and `OpenLive` with one exported `Open(ctx, cfg, log, middlewareName, pluginVersion) (*Client, error)`. Body is today’s shared reclaim Open (DecisionStore, `OwnershipKey`, `New`, hooks, `bindIdentity`) plus `noteStreamOwner`. Do not keep aliases.
- [ ] 1.2 Leave `noteStreamOwner` semantics and warn text as they are. Call it from `Open` for every mode. Do not reconstruct identity: reuse `bindIdentity`, `OwnershipKey`, `SessionHex`.

## 2. Retarget callers

- [ ] 2.1 In `plugin.go` `openOwnedLeg`, replace the `LapiMode` stream/alone vs live branch with one `lapi.Open(bindCtx, config, log, name, pluginVersion)`. Do not read `LapiMode` to pick an entry point.
- [ ] 2.2 Retarget the 52 `OpenStream` / `OpenLive` calls in `pkg/lapi/zzz_severance_test.go`, `zzz_session_test.go`, `zzz_scopeunion_test.go`, `zzz_client_stream_overlap_test.go`, and `zzz_decisionstore_test.go` to `Open`. Test function names that mention OpenStream or OpenLive may stay as scenario labels. Do not add a test-only alias.

## 3. Local verification

- [ ] 3.1 Confirm no remaining `OpenStream` / `OpenLive` definitions or calls under the worktree except historical `openspec/changes/archive/` and other-run `devstate/`.
- [ ] 3.2 Run the existing `pkg/lapi` and constructor unit tests on this machine and report pass, fail, or not run.
- [ ] 3.3 Leave `knowledge/devdocs` Language/usage folds for implement / `opd-devdocsimpact`. Do not rewrite archived OpenSpec change folders.
