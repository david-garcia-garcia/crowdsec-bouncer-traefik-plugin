# Devdocs impact
change: adopt-utilities-v1-0-7

## Units
- Reclaim context lease — subsystem — `pkg/reclaim` / `std_go_reclaim_context-lease`
- DecisionStore — subsystem — `pkg/decisionstore` / `core_plugin_decisionstore_store`
- Decision scopes — subsystem — `pkg/decisionscope` / `core_plugin_decisions_scopes`
- GitHub Actions GOPATH — subsystem — `.github/workflows/main.yml` / `build_ci_github`
- Instance slots — subsystem — `plugin.go` aliases / `core_plugin_middleware_instance-slots`

## Findings
- [x] stale-usage  DecisionStore — `core_plugin_decisionstore` How-to still named SimpleRedis at `v1.0.6`
