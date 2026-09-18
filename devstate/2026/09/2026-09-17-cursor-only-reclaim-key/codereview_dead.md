# Dead

1. [hard] Leftover production path — `pkg/lapi/identity.go:65` — `IdentityHex` has no callers outside tests after `Key` moved to `SessionHex` plus `hashJSON(identityFrom)`
   ```
   func IdentityHex(cfg *configuration.Config) string {
   	b, err := json.Marshal(identityFrom(cfg))
   	if err != nil {
   		return fmt.Sprint(cfg)
   	}
   	return hashBytes(b)
   }
   ```
   Grep `IdentityHex` on the worktree (ignore tests, docs, examples, `openspec/`, `knowledge/`, `devstate/`, `.cursor/`): remaining production hits are this definition and comments in `pkg/lapi/identity.go` and `pkg/lapi/session.go`. Callers are `pkg/lapi/zzz_session_test.go` and `pkg/lapi/zzz_decisionstore_test.go` only. Not `New` / `CreateConfig` / Traefik host contract. (`pkg/appsec.IdentityHex` is a different symbol; this change did not retarget it.)
   → Delete `IdentityHex`; assert via `Key(cfg)` or same-package `hashJSON(identityFrom(cfg))`
   Status: skipped
   Argument: public API; live spec core_plugin_lapi_connection still names IdentityHex as an export. Change tasks keep it exported. Not New/CreateConfig, but deleting it is a host-contract pause.
