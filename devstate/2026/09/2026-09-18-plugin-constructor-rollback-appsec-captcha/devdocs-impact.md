# Devdocs impact

Units this apply touched: `New` (module root), `bouncer.New`, `ValidateParams`, README mode section.

| Finding | Packet | Kind | Action |
|---|---|---|---|
| Overview says `New` "must use the constructor `ctx` as the reclaim holder" — now a derived child | `knowledge/devdocs/core_plugin_middleware.md` | stale usage | taken |
| How-to-use and the pattern snippet pass `config` and `ctx` straight through | `knowledge/devdocs/core_plugin_middleware.md` | stale usage | taken |
| No Language entry for the constructor snapshot or the bind context | `knowledge/devdocs/core_plugin_middleware.md` | Language gap | taken |
| Appsec mode's captcha client is not described, and it is the one mode where it depends on the failure action | `knowledge/devdocs/core_plugin_middleware.md` | missing usage | taken |
| "Call `reclaim.Open` / `OpenWithHooks` with Traefik's `New` ctx" — there is no Release, so a constructor that can fail needs its own child | `knowledge/devdocs/std_go_reclaim.md` | stale usage | taken |
| Nothing records the appsec-plus-disabled warning for whoever reads config validation next | `knowledge/devdocs/core_plugin_middleware.md` | Language gap | taken |

No new packet was needed: both folds land on existing leaves that already own `New` and the reclaim
shim. `core_plugin_appsec.md` and `core_plugin_middleware_captcha-routing.md` were checked and say
nothing that this change makes untrue — routing behaviour once the captcha client is valid is
unchanged.
