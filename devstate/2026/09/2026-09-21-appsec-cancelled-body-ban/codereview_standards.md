# Standards

1. [judgement] Fix the cause — `pkg/appsec/query.go:135-137`, `pkg/appsec/query.go:236-240` — passthrough allow for client-body drop is wired as a package sentinel (`errClientBodyDroppedAllow`) and a `Query` peel, because `resultForFailureActionErr` returns `nil` for passthrough while unreachable and AppSec response-body io failures call `resultForFailureAction` inside `Query` and return allow there
   → Extend the forward-request build seam so passthrough allow uses the same failure-action owner as those siblings (e.g. early structured result from the builder) instead of a second error-space sentinel
   Status: done
   Argument: same as Nitpicks 3 — `Query` maps `errClientBodyDropped` through `resultForFailureAction`.

2. [judgement] Duplicated Code — `pkg/appsec/zzz_query_test.go:49-95` — `assertClientBodyDroppedPassthrough`, `assertClientBodyDroppedBan`, and `assertUnclassifiedBodyReadStillGetBody` repeat the same httptest AppSec server, URL parse, `newQueryClient`, and hit-counter setup with only assertion text differing
   → Extract one helper that returns `(client *Client, hits *int)` (or similar) and keep per-case assertions in the table subtests
   Status: skipped
   Argument: judgement; extract is outside the hard apply set.
