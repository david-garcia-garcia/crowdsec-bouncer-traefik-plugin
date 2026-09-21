# Spec

1. [wrong] `pkg/decisionstore/liveslot.go:49` — `expiryFromDuration` returns `1` when `exp <= 1`; openspec/changes/compact-liveslot-elapsedsec/specs/core_plugin_decisionstore_store/spec.md Requirement: Memory slot expiry uses elapsed seconds — Packing SHALL set `expiresAt` to a saturated int32 in the open interval `(1, MaxInt32]` (endpoint `1` excluded)
   Status: done
   Argument: Spec/design/proposal interval is `[1, MaxInt32]`; 1 remains the already-expired value the predicate still sees.
