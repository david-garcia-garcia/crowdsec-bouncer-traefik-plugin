# [BUG] appsec responding with 502, 503 or 504 should be considered as unavailable

Upstream: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/337 (CLOSED)

## Upstream report

**Describe the bug**
When reaching the appsec endpoint through a proxy (in my case envoy, but would be the same with anything else), setting crowdsecAppsecUnreachableBlock to false has no effect. When using a L7 proxy to reach the appsec endpoint, if appsec is down, the proxy will respond (usually with a 502, 503 or 504 error code). In this case, Traefik will block every requests no matter crowdsecAppsecUnreachableBlock

**Expected behavior**
Appsec endpoint replying with 502, 503 or 504, it should be considered as appsec being unavailable, so crowdsecAppsecUnreachableBlock setting is honored

**Context**
When I shut down crowdsec, traefik replies with a 403 for any req, despite crowdsecAppsecUnreachableBlock being false. In Traefik's logs:
```
time=2026-06-17T08:12:00.559+02:00 level=DEBUG msg="handleNextServeHTTP ip:192.168.7.106 isWaf:true appsecQuery statusCode:503" component=CrowdsecBouncerTraefikPlugin
time=2026-06-17T08:12:00.557+02:00 level=DEBUG msg="ServeHTTP ip:192.168.7.106 isTrusted:false" component=CrowdsecBouncerTraefikPlugin
```

**Version**
- OS: Docker
- Traefik version: 3.7.5
- Plugin version: 1.6.0
- Redis: no

**To Reproduce**
1. Configure so that Traefik -> appsec endpoint is done through an L7 proxy
2. Shutdown crowdsec
3. Try any request: Traefik replies with a 403

## Assessment

- relevant: yes
- kind: bug
- affected: no
- status: present-fixed-unproven
- proof: pkg/appsec/failure_action_test.go, tests/e2e/mock/scenarios/appsec/run.sh
- recommended-action: add-tests
- slug: 2026-09-06-upstream-337-appsec-proxy-unavailable
- rationale: Upstream v1.6.0 logged `appsecQuery statusCode:503` and banned despite `crowdsecAppsecUnreachableBlock: false` because reverse-proxy 502/503/504 fell through the generic non-200 path instead of the unreachable handler. On our `master` tree, `pkg/appsec/query.go` treats transport errors and `isReverseProxyError` statuses (502/503/504 in `pkg/appsec/client.go`) as unreachable and applies unified `crowdsecAppsecFailureAction` via `resultForFailureAction`, replacing the removed `crowdsecAppsecUnreachableBlock` bool (archive `openspec/changes/archive/2026-09-05-lapi-appsec-failure-action/`). Unit tests cover passthrough on transport unreachable and e2e mock covers 502 with default `ban`, but no test asserts passthrough when AppSec returns HTTP 502/503/504.

### Evidence
- current: pkg/appsec/query.go, pkg/appsec/client.go, pkg/configuration/configuration.go, openspec/specs/core_plugin_appsec_failure-action/spec.md
- tests: pkg/appsec/failure_action_test.go (Test_appsecQuery_failureActionOnUnreachable — transport error only), tests/e2e/mock/scenarios/appsec/run.sh (502 with ban only)
