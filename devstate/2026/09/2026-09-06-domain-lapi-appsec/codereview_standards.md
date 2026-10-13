# Standards

1. [hard] Leave a trail — `plugin_test.go:129` — failure strings still say `CrowdsecConnection` after the reclaim type became `lapi.Client` and accessors became `LapiClient`/`SameLapiClient` (same stale noun at `:155`, `:196`, `:219`, `:227`)
   → Reword each `t.Fatal`/`t.Fatalf` to name `lapi.Client` or “LAPI client”
   Status: done
   Argument: Reworded five plugin_test.go fatals to lapi.Client.

2. [hard] Name for the scope — `pkg/appsec/client.go:90` — `closeIdle(client *http.Client)` names the parameter `client` in a package whose reclaim type is `Client`, so readers must decode which client is meant (mirror at `pkg/lapi/client_http.go:34`)
   → Rename the parameter to `httpClient` in both copies
   Status: done
   Argument: Parameter is httpClient in pkg/appsec/client.go and pkg/lapi/client_http.go.

3. [judgement] Symmetry and consistency — `pkg/bouncer/bouncer.go:112` — paired reclaim fields `lapiClient` and `appsecClient` expose `LapiClient()`/`SameLapiClient()` but no symmetric `AppsecClient()`/`SameAppsecClient()` for the AppSec sibling
   → Add matching AppSec accessors or drop the LAPI-only pair if peeking AppSec sharing is out of scope
   Status: skipped
   Argument: judgement; LAPI accessors exist for plugin_test reclaim assertions; AppSec sharing is not asserted in this change.

4. [judgement] Symmetry and consistency — `pkg/appsec/session.go:71` — `Open` inlines `*reclaim.Wrapped` and the post-Open type assert while `pkg/lapi/session.go:272` centralizes the same roles in `wrappedClient` and `clientFromStored` with a Yaegi job comment
   → Extract `wrappedClient` and `clientFromStored` in `pkg/appsec` to match the LAPI reclaim path
   Status: skipped
   Argument: judgement; AppSec has no Sleep/Wake tickers, so a one-Open inline wrap is enough for this split.

5. [judgement] Leave a trail — `pkg/appsec/query_test.go:69` — tests are still named `Test_appsecQuery_*` though the exported entry point was retargeted to `Query`
   → Rename tests to `TestQuery_*` (or `Test_Query_*`) so failure output matches the current API
   Status: skipped
   Argument: judgement; names still identify the AppSec query suite; rename is trail polish, not a hard miss.
