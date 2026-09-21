# Scope

| Ticket | Demand | In diff | Status |
|--------|--------|---------|--------|
| https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/395 | Do not treat client-side body read cancel/disconnect as an AppSec ban; honor failure-action spirit; distinguish client-gone errors from unclassified read faults | `pkg/appsec/query.go` (`isClientGoneBodyReadErr`, `newAppsecBodyRequest`, `Query` allow path); `pkg/appsec/zzz_query_test.go` | OK |
| https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/395 | Fork: prove #395 present or absent on this tree via automated test | `pkg/appsec/zzz_query_test.go` `Test_appsecQuery_clientBodyDroppedFailureAction` (cites #395) | OK |
| https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/395 | Delivery: upstream issue URL on the delivery card (reporting only) | not seen | Issue |

1. [judgement] Scope vs Requirements — `requirement.md` Desired requires the upstream issue URL on the delivery card. The pinned diff has product and OpenSpec hunks only; no delivery-card or equivalent devstate reporting change appears in the pin.
   → Confirm the URL is on the delivery card at pullrequest (or add a committed card artifact if that is this repo’s convention).
   Status: skipped
   Argument: demand gap on card reporting; URL is deliverreview/PR summary, not the product pin.
