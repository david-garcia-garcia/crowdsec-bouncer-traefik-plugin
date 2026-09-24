# Deviations

- explore: fix `pkg/reclaim/zzz_alias_test.go` `watchInto` to `Store` a new `*Box` each update (same publish shape as Finding 1). Requirement Affected lists only `pkg/bouncer/bouncer.go`; Unknowns asked whether other watchers mutate `Box.Value` — this test helper does. Bounded incidental reshape of an existing test helper so tests do not re-teach the race.
