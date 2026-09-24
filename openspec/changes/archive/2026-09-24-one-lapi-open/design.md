## Context

See proposal.md Why. `openOwnedLeg` still branches `LapiMode` stream/alone → `lapi.OpenStream`, else `lapi.OpenLive` (`plugin.go`). Both reclaim on `OwnershipKey`, Peek/Open the DecisionStore, `New`, hooks, and `bindIdentity`. `OpenStream` then calls `noteStreamOwner`, which returns unless `LapiMode` is stream or alone (`pkg/lapi/session.go:168-170`). `LapiMode` already lives on the `Config` that `lapi.New` reads. Explore Decisions are accepted: one `Open`, remove the split, retarget call sites, keep `noteStreamOwner` inside `Open`, keep identity owners.

## Goals / Non-Goals

**Goals:**

- One exported `lapi.Open` with the same signature as `appsec.Open` / `captcha.Open`.
- `plugin.go` LAPI own-axis is one call. Mode stays on `Config`.
- `noteStreamOwner` always runs from `Open` and stays a no-op for live/none.

**Non-Goals:**

- Aliases for `OpenStream` / `OpenLive`.
- Changing stream/live/none/alone runtime, collision warn text, or `dropStreamOwner`.
- Changing AppSec or captcha `Open`, config keys, or `LapiMode` validation.
- Reconstructing Host, tenant, user, or trust hop. Reuse `bindIdentity`, `OwnershipKey`, `SessionHex`.
- Writing `knowledge/devdocs` packets in this phase (implement / `opd-devdocsimpact` fold them).
- Rewriting archived OpenSpec folders or other-run `devstate`.

## Decisions

| Topic | Choice | Rationale |
|-------|--------|-----------|
| Entry point | One `Open(ctx, cfg, log, middlewareName, pluginVersion) (*Client, error)` | Same signature as `appsec.Open` / `captcha.Open`. Constructor does not pick a mode entry. |
| Old exports | Remove `OpenStream` and `OpenLive`. No aliases. | Desired is one `Open`. Aliases keep the consumer split as a public surface. |
| Collision log | Call `noteStreamOwner` from `Open` for every mode | Helper already returns before the mutex when mode is not stream or alone, and again when `LapiKey` is empty. `dropStreamOwner` already runs from `Client.Close`. |
| Identity | Reuse `bindIdentity`, `OwnershipKey`, `SessionHex` | Explore identity-owner Decision. Do not reconstruct Host, tenant, user, or trust hop. |
| Tests | Retarget 52 calls to `Open`. Keep function names that mention OpenStream or OpenLive as scenario labels. No test-only alias. | Blast radius is the enumerated call sites. Scenario names still describe mode. |
| Catalog | Fold `core_plugin_lapi_connection` and `core_plugin_decisionstore_store`. No new family. | Live promises already live there. `core_plugin_lapi_reclaim-key` collision SHALL stays. |

**Alternatives rejected:** keep aliases; leave the mode branch in `plugin.go` and only dedupe the body; change collision semantics or LAPI mode runtime; a new spec family; rewrite archived OpenSpec folders.

## Risks / Trade-offs

- **52 test call sites plus two production calls must move together** → Implement walks the explore inventory. Compile fails if a leftover `OpenStream` / `OpenLive` remains.
- **Live/none now enter `noteStreamOwner`** → Early return before `streamOwners` lock. No process-global write. Same as dest for those modes.
- **Stale usage packets** → Enough to call the subsystems. Implement / `opd-devdocsimpact` fold them.

## Migration Plan

- Same binary, same YAML. No operator rename.
- Rollback is revert of the PR.

## Open Questions

None. Explore rows this phase took stay on `explore.md`.
