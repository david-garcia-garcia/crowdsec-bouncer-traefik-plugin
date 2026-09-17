# Issues

- [ ] note large  `pkg/appsec/query.go` reverse-proxy 502/503/504 return without `drainResponse`
  Why: `Query` returns `resultForFailureAction` on `isReverseProxyError` before `defer drainResponse`, so the AppSec HTTP body is not consumed or closed on that path. Transport errors have no body. This ticket is add-tests only.
  Current: `pkg/appsec/query.go` Query unreachable branch
  Proposed: drain or close the response before returning on reverse-proxy statuses (same as the 500 path)
