# Ticket source: stream apply deleted before new

fetchAndApplyStreamDecisions applies stream.New before stream.Deleted (`pkg/lapi/client_stream.go:122-149`), so a same-window replacement (new ban + deleted prior for the same IP or CIDR) disappears. Official CrowdSec bouncers apply deleted first. Proven FAIL: TestHunt_StreamAppliesDeletedBeforeNew and TestHunt_StreamRangeAppliesDeletedBeforeNew. Fix: apply deleted (IP/header delete and Range removals) before new (store and Range upserts). Include regression tests for IP and Range. Bound the ask to this defect only.
