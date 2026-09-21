# Store-owned active_decisions gauge; drop MetricsReporter per-slot map

Problem: MetricsReporter keeps activeDecisionSlots (one entry per Ip/header/Range record) plus activeDecisionsByOriginIPType so stream/alone can POST LAPI usage-metrics active_decisions. At hundreds of thousands of IP decisions that slot map is a second copy of every store key. Origin is already packed on DecisionStore LiveSlot.Word (memory) / KindOriginString (Redis).

Desired:
1. DecisionStore owns the active-record group-by: compact {originID uint16, family} → int64, updated inside PutMany/DeleteMany (memory: under the same mu as putSlot/deleteTickLocked; Redis: MGET previous origin then adjust in-process counts). PublishTick memory expiry SHOULD decrement when a slot is swept (free correctness vs today).
2. MetricsReporter MUST NOT keep activeDecisionSlots or activeDecisionsByOriginIPType. reportMetrics snapshots store counts and emits origin names via OriginName at POST. Dropped window + processed atomics stay on the reporter.
3. Count only stream/alone Ip and header-scope mutations. Live/none Put memo MUST NOT increment. OpenDecisionStore/New sets a countActive (or equivalent) from lapiMode; reporter still omits active_decisions unless stream/alone.
4. Do not store usageMetricKey / LAPI item JSON shape in decisionstore.
5. Do not add a Go interface for the engine (Yaegi: funcs on engine struct only). Store method(s) to read counts for POST are fine.
6. Remove rememberActiveDecision/forgetActiveDecision from stream apply for Ip/header (store mutations carry the gauge). Range: do not forget/peek membership; Range is out of the gauge until debt is taken (omit Range from counts — not +1 on New with no Deleted).
7. Spec fold: core_plugin_lapi_usage-metrics (drop per-slot forget map requirement; reporter snapshots store) and core_plugin_decisionstore_store (store owns the group-by). FindSpecHost / speclibrarian. Keep intern overflow origin id 0 / empty OriginName.
8. Include knowledge/debt/2026-09-20-range-active-decisions-forget.md in this change (Range ApplyRangeBatch displacements later). Recreate it in the worktree if dest does not have it. Append issues.md note large row. Update IssueKey inside that debt file to 2026-09-20-store-active-decisions-gauge.

Out of scope: Range exact-CIDR forget / ApplyRangeBatch displacements (debt). Querying RangeMembership.Remediation / Helper.Contains for metrics. Redis intern table. Replacing tick maps. Counting live/none memo. N decisions per cache key. New public config. Patching vendor iplookup.

Current code (re-ground on dest in the worktree):
- pkg/lapi/client_metrics.go activeDecisionSlots + activeDecisionsByOriginIPType, remember/forget
- pkg/lapi/client_stream.go and client_decisions.go remember/forget around Put/Delete and range:+cidr
- pkg/decisionstore/memory.go putSlot, DeleteMany, PublishTick
- pkg/decisionstore/redis.go PutMany MSetEX / DeleteMany DEL without GET
- openspec/specs/core_plugin_lapi_usage-metrics/spec.md requirement Active-decision slots store intern id and family
- knowledge/devdocs/core_plugin_lapi_usage-metrics.md Compact decision slot language

Debt file body to land (adjust IssueKey as specified) — this is desired work for later phases; requirement.md must include it:
# Range active_decisions forget after dropping the slot map
Why: Range is a blob + LPM trees, not a slot Peek. ApplyRangeBatch displacements are the later take. Until then omit Range from the store-owned gauge.
Why not taken: ship Ip/header store-owned counts first. Helper has no exact-prefix get; do not patch vendor iplookup; do not LPM a network IP.
Risks: cscli active_decisions omits Range CIDRs (accepted). Do not "fix" with LookupRemediation or RangeMembership.Remediation.
