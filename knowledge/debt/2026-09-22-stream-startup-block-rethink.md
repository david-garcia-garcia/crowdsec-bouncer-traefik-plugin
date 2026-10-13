# Stream startup block still means more than "published"

Resolved: `bouncerStartupBlock` was removed. A missing subscribed client uses that leg's failure action.

IssueKey: 2026-09-22-bouncer-instance-severance
Size: large
Action: note

## Why this follow-up

The public name said "wait until the stream cache is warm." On the request path it only asked whether every subscribed client was published. A published client counted as ready while the first poll was still in flight, and `New` did not wait. The knob overlapped the per-leg failure action for that unpublished window, so it was removed rather than renamed.

## Why it was not taken

This change had to stop blocking Traefik `New`. Tightening "ready" to first-poll complete was a later product decision. Removing the knob closed the overlap: unpublished LAPI and AppSec use their failure action, and an unpublished captcha client bans a captcha verdict.

## Risks

Operators who set the old key still have it ignored by encoding. Until a client is published, the default failure action is ban.

## Context

Owner: bouncer request path (`pkg/bouncer`). Not LAPI `startStream`. The first poll stays asynchronous.
