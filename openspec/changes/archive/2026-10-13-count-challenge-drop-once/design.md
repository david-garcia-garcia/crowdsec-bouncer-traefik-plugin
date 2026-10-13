## Context

See proposal.md Why. Dest `appsecQuery` treats HTTP 200 as allow and any other non-500 status as an error that `handleNextServeHTTP` bans. The AppSec body is drained, not parsed. `blockedRequests` is a process-wide `int64`; `reportMetrics` posts one `dropped` request item with `{type: traefik_plugin}`.

## Goals / Non-Goals

**Goals:**

- Relay a parsed `action: challenge` envelope to the client.
- Count that relay once, on the challenge page, not on `/crowdsec-internal/challenge/*`.
- Keep ban and `pkg/captcha` increment sites as they are.

**Non-Goals:**

- Origin or remediation labels, a bytes series, or any other metrics POST change.
- AppSec `captcha` action, 404-on-unanswered challenge path, unexpected-status failure action (sibling tickets).
- Merging upstream #343 wholesale or copying PR 403's patch.

## Decisions

- Parse JSON in `appsecQuery` after a successful HTTP round-trip (including 403). A non-empty `action` is a structured result with a nil error so `handleNextServeHTTP` can branch. HTTP 200 with no action stays allow. HTTP 500 and unreachable stay on the existing failure flags. Alternatives: parse only in the bouncer after a 403 error string — rejected because the body would already be drained.
- Write the envelope in a dedicated method (`handleAppsecResponseServeHTTP`) so the skip lives next to the increment it gates. Alternatives: skip inside `handleBanServeHTTP` by path — rejected; that uncounts bans.
- Skip when `strings.HasPrefix(req.URL.Path, "/crowdsec-internal/challenge/")`. Alternatives: list fpscanner/pow-worker/submit only — rejected; the protocol uses the prefix, and a custom script path sits under it too.
- Do not increment on the prefix even for a successful submit. The page already counted.

## Risks / Trade-offs

- [Dest grows a real challenge relay here, overlapping #343] → Keep the parse/write to `action: challenge` only; other actions still ban as today.
- [Empty challenge body] → Write status/headers/cookies anyway; do not substitute the operator ban page on this ticket (empty-body fail-closed is a different protocol row, not this skip).
- [Path prefix matches a non-challenge ban] → Ban path is unchanged; the skip is only on the challenge-relay increment.

## Migration Plan

None. Counter is in-memory per process; no stored shape.
