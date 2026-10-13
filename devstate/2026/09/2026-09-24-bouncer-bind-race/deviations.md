# Deviations

- [ ] proposed  include `watchInto` Box publish fix with Finding 1
  Asked: Affected lists only `pkg/bouncer/bouncer.go` (`storeBinding` and its three Receive* callers).
  Instead: also change `pkg/reclaim/zzz_alias_test.go` `watchInto` to `Store` a new `*Box` each update (same publish shape).
  Owner: `pkg/reclaim/zzz_alias_test.go`
  Why: Unknowns asked whether other watchers mutate `Box.Value`; this test helper does, and leaving it teaches the race. Bounded incidental companion to the named fix.
  By: explore
  Requester: not asked
