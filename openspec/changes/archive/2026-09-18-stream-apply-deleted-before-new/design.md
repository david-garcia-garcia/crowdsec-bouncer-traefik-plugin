## Context

See `proposal.md` Why. Dest `fetchAndApplyStreamDecisions` loops `stream.New` then `stream.Deleted`, then `ApplyRangeBatch` upserts then removes (`pkg/lapi/client_stream.go`, `pkg/decisionscope/range.go`). Official lua-cs-bouncer and cs-firewall-bouncer apply deleted then new (`knowledge/research/ext_crowdsec_bouncers_stream-apply/`). LAPI can put the same IP or CIDR in both arrays. JSON field order on this pin is `new` then `deleted` — do not follow that.

FindSpecHost:

```
verdicts:
  - { deltaId: stream-apply-deleted-before-new, fold|new: new, spec-id: core_plugin_lapi_stream-apply, confidence: high, candidates: [core_plugin_lapi_stream-lease, core_plugin_lapi_stream-single-flight, core_plugin_decisions_scopes, core_plugin_lapi_stream-apply] }
```

Search: family `core_plugin_lapi` leaves `stream-lease` (`updated` acquire) and `stream-single-flight` (intra-Client poll lock). `core_plugin_decisions_scopes` is request matching, not stream write order. Apply-deleted-before-new is a new capability, not a one–three-requirement bugfix of those leaves. New usage packet `core_plugin_lapi_stream-apply.md` already names this unit.

## Goals / Non-Goals

**Goals:**

- One stream payload that replaces an Ip or Range decision leaves the replacement active.
- Range stays one `ApplyRangeBatch` (one read, one write) with removals before upserts.
- Two hunt regressions fail on dest order and pass after the swap.

**Non-Goals:**

- Changing the stream lease or single-flight.
- Two `ApplyRangeBatch` calls per tick.
- A header-only hunt test (header delete/store rides the same loops).
- Reordering LAPI JSON fields or the `Stream` struct.
- Live/none, AppSec, captcha, reclaim, metrics reporter.

## Decisions

1. **Swap the two loops in `fetchAndApplyStreamDecisions`.** Deleted first, then New. Alternative: apply by JSON field order — rejected (`new` is first on the wire; official bouncers key by name and apply deleted first).
2. **Change `ApplyRangeBatch` internal order** (removals then upserts). Alternative: two batch calls — rejected (breaks the one-read/one-write Range-index invariant). One-sided `AddRange` / `RemoveRange` stay equivalent.
3. **Forget then remember** rides the same loop swap (`forgetActiveDecision` on delete, `rememberActiveDecision` on store).
4. **Hunt tests in `zzz_client_stream_test.go`.** Reuse `newTestRangeClient` / stream stub helpers. Names: `TestHunt_StreamAppliesDeletedBeforeNew` and `TestHunt_StreamRangeAppliesDeletedBeforeNew`.
5. **New spec leaf** `core_plugin_lapi_stream-apply`. Do not fold into `stream-lease` or `decisions_scopes`.

## Risks / Trade-offs

- [A CIDR only in removals then re-added in upserts is a no-op vs dest if dest already had it] → Same-window replacement is the case dest gets wrong; delete-only still clears because no upsert remains.
- [Changing `ApplyRangeBatch` order is visible to any caller that passes both maps] → Stream is the only caller that fills both; one-sided callers unchanged.

## Migration Plan

No operator JSON/YAML key change. Rollback is revert.
