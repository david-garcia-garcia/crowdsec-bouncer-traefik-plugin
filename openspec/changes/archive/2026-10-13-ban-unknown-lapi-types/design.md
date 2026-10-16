## Context

See proposal.md for why. On master, RemediationValue maps only an and captcha. Four LAPI ingest sites skip empty kind: streamPutItem, Range upsert in handleStreamCache, strongestLiveDecision, and queryLiveDecisions. Origin remap calls RemediationValue on the operator to-token and needs empty to mean not a code. logger.Trace already exists; slog has no Trace method.

## Goals / Non-Goals

**Goals:**
- One LAPI ingest helper maps wire type to store kind and TRACE-logs unknown types.
- All four ingest sites call it. Unknown becomes BannedValue. Ban still beats captcha in live pick.
- Tests fail on master if an unknown type is skipped or allowed.

**Non-Goals:**
- Changing RemediationValue.
- AppSec challenge relay, metrics, captcha, workflow files.
- Copying upstream PR 403's root ouncer.go patch.
- Taking whitelist semantics for type llow.

## Decisions

- Helper in pkg/lapi, not in pkg/decisionscope. Keep empty RemediationValue for remap. Alternative: change RemediationValue default to ban — rejected by the ticket and remap callers.
- Range uses the same helper. Alternative: only streamPutItem and live — rejected; Desired is stream store and apply, and Range is the fourth ingest site.
- strongestLiveDecision uses ingest kind so unknown outranks captcha (ban wins). Alternative: map after pick — would let captcha win over challenge.
- TRACE via logger.Trace with stem handleStreamCache:unknownType on the helper, including live. Alternative: Info — floods; Debug — ticket forbids.

## Risks / Trade-offs

- [type llow becomes ban] → operators who expected allow-as-whitelist lose that gap; existing debt file stays; ticket names llow.
- [TRACE stem says handleStreamCache on live] → matches the asked stem; live items share the same message.
- [unknown type on every stream item] → TRACE only, so default Info operators are not flooded.

## Migration Plan

- Deploy as a fail-closed ingest change. No persisted schema change. Rollback restores skip/allow for unknown types.
