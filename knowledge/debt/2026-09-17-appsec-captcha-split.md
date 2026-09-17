# Split AppSec and captcha off the LAPI transport ticket

IssueKey: 2026-09-17-lapi-transport-router-policy
Size: large
Action: note

## Why this follow-up
AppSec already has its own Client and per-router failure action. Captcha stays on Bouncer. This change only moved LAPI policy.

## Why it was not taken
Out of scope. Ticket forbids AppSec and captcha work in this apply.

## Risks
A later AppSec TLS reload may still split the AppSec reclaim key the way LAPI TLS used to.
