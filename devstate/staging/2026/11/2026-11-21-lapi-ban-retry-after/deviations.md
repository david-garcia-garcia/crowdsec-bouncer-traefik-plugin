# Deviations

- [x] taken  Range-scope bans in live/none keep Retry-After; the Range exception holds for stream/alone only
  Asked: decision 4 — "Range-scope bans carry no `Retry-After` in this change (the Range-index blob has no end)".
  Instead: stream/alone Range bans (served from the Range-index blob) carry no header. In live/none, LAPI expands Range on the `?ip=` query and returns the decision with its `Duration`, so that ban carries `Retry-After` like any other LAPI ban answered 429.
  Owner: `pkg/lapi/client_decisions.go` (`queryLiveDecisions` parses the chosen decision's duration whatever its scope)
  Why: decision 4's reason is the blob, which only stream/alone read. Following the letter in live/none would add a scope check to `queryLiveDecisions` only to hide an end it already knows.
  By: explore
  Requester: not asked
