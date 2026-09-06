## 1. Constructor rollback and guard

- [x] 1.1 Add `bindCtx` wrapper in `plugin.go` `New`; cancel on error return
- [x] 1.2 Reject `appsec` mode when `crowdsecAppsecEnabled` is false

## 2. Plugin tests

- [x] 2.1 Test appsec-mode without enabled is rejected
- [x] 2.2 Test appsec-only skips LAPI and binds AppSec reclaim key
- [x] 2.3 Test live+AppSec uses distinct LAPI and AppSec reclaim keys
- [x] 2.4 Test AppSec open failure after LAPI rolls back LAPI holder
- [x] 2.5 Test stream mode opens stream session; alone failure leaves no holders

## 3. Spec

- [x] 3.1 Fold requirements into `core_plugin_middleware_instance-reclaim`
