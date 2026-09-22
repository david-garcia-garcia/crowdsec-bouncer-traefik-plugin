# Stream startup block still means more than "published"

IssueKey: 2026-09-22-bouncer-instance-severance
Size: large
Action: note

## Why this follow-up

`streamStartupBlock` still uses a name that says stream startup. On the request path, `true` now asks whether every backend this bouncer subscribes to is published. One subscription checks only that backend. A published client counts as ready even while the first stream poll is in flight. `New` must not wait. What "ready" should mean past "the subscribed client is published", and whether the knob should be renamed, are still open.

## Why it was not taken

This change had to stop blocking Traefik `New`. Tightening "ready" to first-poll complete, or renaming the public YAML key, is a later product decision with operator-visible semantics.

## Risks

Operators who read `streamStartupBlock` as "wait until the stream cache is warm" can see 200/403 from an empty store after the client is published. A later rename is a breaking public-key change.

## Context

Owner: bouncer request path (`pkg/bouncer`). Not LAPI `startStream`. Default stays true.
