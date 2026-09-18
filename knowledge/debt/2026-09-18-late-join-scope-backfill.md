# A scope that joins the union late misses already-streamed decisions

IssueKey: 2026-09-17-cursor-only-reclaim-key
Size: medium
Action: note

## Why this follow-up
Live routers now union their header scopes onto the shared stream Client (`pkg/lapi/liveheaderscopes.go`, registered after bind in `pkg/lapi/session.go`). When a router starts after the shared poller has already advanced the CrowdSec cursor, the union grows but the next poll still goes out with `startup=false` (`pkg/lapi/client_decisions.go:16` only sets `startup=true` when the stream is unhealthy or still on first-create startup).

CrowdSec answers a non-startup poll with decisions newer than `id_gt`. Decisions for the newly added scope that were emitted before the router joined are therefore never delivered, and the joiner behaves as if that scope had no bans until some later incarnation polls with `startup=true`. The observable case is a Country router attached to a router set that was already streaming `ip,range`: existing Country bans stay invisible to it.

Bounded and tested: `pkg/lapi/zzz_scopeunion_test.go:75-108` asserts the late join keeps `startup=false`, and the window is documented in `knowledge/devdocs/core_plugin_lapi_scope-union.md:36`.

## Proposed shape
Two candidates, neither costed yet. Re-poll once with `startup=true` when the union gains a scope that was not previously requested, which is correct but re-downloads the whole decision set on every new router and needs a guard against reload storms. Or keep the incremental poll and backfill only the added scopes through a one-shot query, which is cheaper but adds a second request shape to `pkg/lapi`.

## Why it was not taken
Accepted knowingly by the repository owner when PR #67 was reviewed, as a bound rather than a bug. The alternative was to hold the whole cursor-only reclaim series for a refetch policy that needs its own design.

## Risks
A router that adds a scope after startup under-blocks for that scope until the next `startup=true` poll, which in a stable deployment may not happen until Traefik restarts.
