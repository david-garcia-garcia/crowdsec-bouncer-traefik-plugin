# Security

1. [judgement] Client-controlled trust — `pkg/bouncer/bouncer.go:570` — the dropped-metric skip keys on the client-chosen request path, so any AppSec envelope for a request under `/crowdsec-internal/challenge/` goes uncounted, not only the solve callbacks
   Fix: Document that this only under-counts usage metrics (no allow/deny effect); optionally also require the envelope to be a challenge action.
   Status: skipped
   Argument: Judgement, not applied. The skip only lowers the usage-metrics `dropped` count; the relay, the AppSec verdict and allow/deny are unchanged, so a client choosing the path gains nothing but an uncounted drop. Path-only scope is the explore decision (Open question 3); after #206 only `challenge` and bodied unknown actions reach the relay.
