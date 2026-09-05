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
2. [hard] Timeout on a reused conn was retried (~2s tail) — `pkg/simpleredis/simpleredis.go:137`
   → Applied: `errTimeout` returns without a second dial

Standards: 1 finding, worst: Leave a trail at handshakeCounts (applied)
Spec: 0 findings, worst: none
Security: 0 findings, worst: none
Performance: 2 findings, worst: Close-skipping retry dial (applied)

## Applied
- Standards 1: job comment on `handshakeCounts`
- Performance 1: stale retry uses `borrow` so Close cannot redial
- Performance 2: timeout on a reused conn is not retried
- Yaegi: `ioError` uses `errors.Is(os.ErrDeadlineExceeded)` instead of a `net.Error` assert

## Recorded and skipped
none.
