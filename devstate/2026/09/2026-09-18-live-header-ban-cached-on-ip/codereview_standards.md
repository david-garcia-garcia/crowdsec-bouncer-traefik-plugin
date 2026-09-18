# Standards

1. [hard] Leave a trail — `pkg/lapi/client_live.go:25` — edited `handleNoStreamCache` has no method comment that states the job (query IP plus headers, write the IP query result to the client-address key, return the merge)
   → Add a succinct method comment on `handleNoStreamCache`
   Status: done
   Argument: added method comment on handleNoStreamCache.
