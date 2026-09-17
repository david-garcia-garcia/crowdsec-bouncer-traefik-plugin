# AppSec and captcha surfaces unchanged

IssueKey: 2026-09-17-lapi-transport-router-policy
Size: large
Action: note

## Why this follow-up
Ticket explicitly excludes AppSec, captcha, and related middleware behavior from the LAPI lifetime refactor.

## Why it was not taken
Binding out-of-scope per ticket; no coupling required to move per-router LAPI policy and transport off the cursor hash.

## Risks
None for this change; AppSec/captcha lifetime issues remain on their own tracks.
