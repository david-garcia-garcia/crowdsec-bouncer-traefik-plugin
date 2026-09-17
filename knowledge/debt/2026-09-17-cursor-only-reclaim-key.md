# Narrow the LAPI reclaim key to the CrowdSec cursor row

IssueKey: 2026-09-17-lapi-transport-router-policy
Size: large
Action: note

## Why this follow-up
CrowdSec stores `GET /v1/decisions/stream` progress on one bouncer row (hashed key + outbound IP). This plugin still keys reclaim by session prefix plus a first-wins settings hash, and uses `PeekLivePrefix` when a joiner disagrees.

## Why it was not taken
Out of scope. Narrowing to cursor-only would delete Peek, union `scopes=`, or replace `pkg/reclaim`.

## Risks
A remaining-settings mismatch still warn-and-wires instead of sharing one cursor-shaped key.
