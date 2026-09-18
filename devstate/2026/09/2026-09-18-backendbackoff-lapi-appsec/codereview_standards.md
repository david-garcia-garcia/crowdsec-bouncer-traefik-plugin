# Standards

1. [hard] Leave a trail — `pkg/lapi/client_decisions.go:98` — `admitLiveGET` collapses Allow-error (`ctx.Err`, `errClosed`) and deny into `errQuerySkipped` and drops the cause
   → Keep the skip prefix; wrap or Debug-log the Allow error so the classified failure stays
   Status: done
   Argument: 9661262 admitLiveGET Debug-logs err and wraps Allow-error as `queryLiveDecisions:skipped: %w`.
2. [hard] Leave a trail — `pkg/appsec/query.go:178` — `admitQuery` collapses Allow-error and deny into a fresh `appsecQuery:skipped` and drops the cause
   → Keep the skip prefix; wrap or Debug-log the Allow error so the classified failure stays
   Status: done
   Argument: 9661262 admitQuery Debug-logs err and wraps Allow-error as `appsecQuery:skipped: %w`.
3. [judgement] Duplicated Code — `pkg/lapi/client_decisions.go:93` and `pkg/appsec/query.go:173` — admit/report helpers are the same shape with different stem and skip string
   → Leave the twins; each package owns its Gate and skip message
   Status: skipped
   Argument: judgement; each package owns its Gate and skip string.
4. [judgement] Leave a trail — `pkg/lapi/client.go:40` and `pkg/appsec/client.go:15` — Client type comments omit the Gate this change added
   → Mention the live/none or AppSec Gate in the type comment
   Status: skipped
   Argument: judgement; comments remain true.
