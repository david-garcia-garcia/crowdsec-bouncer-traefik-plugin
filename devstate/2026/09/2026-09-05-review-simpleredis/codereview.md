# Codereview
pin: origin/master...HEAD (aacf795) excluding destate/ and .cursor/

## Standards
1. [hard] Leave a trail — `pkg/simpleredis/simpleredis_test.go:87` — `handshakeCounts` had no job comment
   → Applied: one-line comment on the helper

## Spec
none.

## Security
none.

## Performance
1. [hard] After a dead pooled conn, `exec` retried with `dial()` and skipped `closed` — `pkg/simpleredis/simpleredis.go:140`
   → Applied: retry goes through `borrow`

Standards: 1 finding, worst: Leave a trail at handshakeCounts (applied)
Spec: 0 findings, worst: none
Security: 0 findings, worst: none
Performance: 1 finding, worst: Close-skipping retry dial (applied)

## Applied
- Standards 1: job comment on `handshakeCounts`
- Performance 1: stale retry uses `borrow` so Close cannot redial

## Recorded and skipped
none.
