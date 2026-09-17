# Share one DecisionStore across LAPI Clients

IssueKey: 2026-09-17-lapi-transport-router-policy
Size: large
Action: note

## Why this follow-up
Two Clients still each own an isolated `cache.Client`. A shared DecisionStore (and reclaim of that cache, including an atomic Redis `updated` lease) would let routers share remediations without sharing a LAPI poller.

## Why it was not taken
Out of scope for this change. Ticket forbids implementing a shared store or cache reclaim.

## Risks
Two in-process Clients on different reclaim keys still keep two caches and two Redis `updated` leases.
