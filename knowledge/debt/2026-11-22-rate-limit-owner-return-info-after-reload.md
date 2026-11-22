# Log owner-available after a reload that rebuilds a subscriber after its owner

IssueKey: 2026-11-20-add-redis-rate-limit-leg
Size: large
Action: note

## Why this follow-up

A rate-limit subscriber logs WARN `crowdsec bouncer rate limit owner unavailable` when its owner goes away, and INFO `crowdsec bouncer rate limit owner available` on the next bind of the same subscriber instance. When the owner comes back through a file-provider reload, Traefik rebuilds every middleware of that provider in an order it does not fix. A subscriber rebuilt after the owner binds at once and logs neither line, so the WARN its previous instance logged is never answered by an INFO. Measured on real Traefik v3.7.19 (2026-11-22, `rate_limit_shared.Tests.ps1`): on one restore `rl-shared-b` logged WARN then INFO, `rl-shared-a` logged nothing; on another both logged WARN then INFO.

## Why it was not taken

Found while making the real-stack case robust in round 2 addendum C; the owner-loss logging (dcfd0393) keeps its state per subscriber instance, and carrying it across a rebuild needs a process-wide record keyed by subscriber name and instance name, a design choice the human has not made. The Pester case now asserts what the code guarantees: every WARN logged since the restore is followed by an INFO of the same subscriber.

## Risks

An operator who alerts on the WARN and clears on the INFO can keep a stale alert for a subscriber that is charging again.

## Context

Current: `pkg/bouncer/bouncer_leg_ratelimit.go` (`warnRateLimitOwnerUnavailable`, `bindRateLimitClient`), `pkg/bouncer/bouncer.go` (`rateLimitOwnerWarned`, one per `Bouncer`).
Proposed: keep "warned" per (traefikName, instanceName) in a process-wide table that a rebuilt subscriber reads on its first bind, or log INFO on the first bind of a rebuilt subscriber whose name has an unanswered WARN.
