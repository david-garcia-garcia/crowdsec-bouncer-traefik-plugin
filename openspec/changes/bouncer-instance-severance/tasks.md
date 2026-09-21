# Tasks

## 1. Config surface
- [ ] 1.1 Rename `Config` fields and JSON tags to `lapi*` / `appsec*` / `bouncer*` domains; keep `log*` and `httpTimeoutSeconds`; add `LapiEnabled`, `LapiInstance`, `AppsecInstance`, `BouncerHold`; default `LapiEnabled` true; remove `AppsecMode`
- [ ] 1.2 Rewrite `ValidateParams` for enable/instance/secrets/`bouncerHold`; update `GetVariable` call sites to new field names
- [ ] 1.3 Update `zzz_configuration*.go` and `zzz_appsec_mode_test.go` (AppSec-only = `lapiEnabled` false)

## 2. Named slots
- [ ] 2.1 Add `pkg/instance` Publish/Peek/ResetForTest for LAPI and AppSec (`atomic.Value`)
- [ ] 2.2 `plugin.go` Open+Publish vs subscribe; `createdBy` = instance name; skip Open when `lapiEnabled`/`appsecEnabled` false
- [ ] 2.3 Holder handler: `bouncerHold` → 503

## 3. Bouncer request path
- [ ] 3.1 `bouncer.New` stores instance names and enable flags, not Client pointers
- [ ] 3.2 `ServeHTTP` Peeks; miss uses failure actions; `lapiEnabled` false skips LAPI lookup
- [ ] 3.3 Opener-only `registerLiveHeaderScopes`; stop subscriber union
- [ ] 3.4 Update `pkg/lapi` exclusive Peek to instance name; field reads of renamed config

## 4. Tests, docs, fixtures
- [ ] 4.1 Unit tests: late bind, hold 503, instance exclusive, subscribe without key
- [ ] 4.2 E2E `tests/e2e/**/*.yml` and `examples/**` new keys; add a subscribe scenario if cheap
- [ ] 4.3 README + `docs/modes.md`: one-middleware, named share, optional dummy, `lapiMode` table without `appsec`

## 5. Specs usage
- [ ] 5.1 Live spec key names in `openspec/specs/**` that this change folds
- [ ] 5.2 Usage packets `knowledge/devdocs/core_plugin_middleware.md` and `core_plugin_middleware_config-validation.md`
