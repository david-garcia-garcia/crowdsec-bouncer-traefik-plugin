# Explore

## Concepts

Flat public Config keys, no nesting, no old-key aliases. Each operator key starts with the piece that reads it (`lapi`, `appsec`, `bouncer`). The `crowdsec` syllable goes away. `httpTimeoutSeconds` and `EffectiveHTTPTimeoutSeconds` go away. The prefix is the operator's label: it stays on `configuration.Config` (Go field and JSON tag) and drops at the package that owns the value.

```
YAML / Traefik labels  (json tags: lapiHost, appsecHost, bouncerEnabled)
        │
        ▼
configuration.Config   prefix stays (LapiHost, AppsecHost, BouncerEnabled)
        │
        ├─ GetVariable(cfg, "LapiKey")     string = new Go field name
        │
        ├─ pkg/lapi   identity / ownership / session   prefix drops (Scheme, Host, Key)
        ├─ pkg/appsec identity / session               already dropped; TLS*Bouncer → TLSClient*
        └─ pkg/bouncer / pkg/captcha                   prefix drops; captcha already local
```

Units this change would touch:

| Unit | Path | Job |
| --- | --- | --- |
| Public Config | `pkg/configuration/configuration.go` | Go fields + JSON tags + `New` defaults + `ValidateParams` + `GetVariable` |
| Plugin entry | `plugin.go` | `CreateConfig` returns `configuration.New()` only; comments name old flags |
| Yaegi testData | `.traefik.yml` | `Enabled` / `CrowdsecLapiKey` Go field names |
| LAPI identity JSON | `pkg/lapi/identity.go` | `identity` + `ownership` marshalers; reclaim hash |
| LAPI HTTP | `pkg/lapi/client.go`, `client_http.go`, `decisionstore.go` | GetVariable, transport timeout, Redis `storeParams` |
| AppSec identity JSON | `pkg/appsec/session.go` | AppSec marshaler; TLS*Bouncer still |
| AppSec HTTP | `pkg/appsec/client.go`, `client_http.go` | GetVariable, transport timeout, scheme/key copy |
| Bouncer | `pkg/bouncer/bouncer.go` | Captcha GetVariable, siteverify client timeout, `streamStartupBlock` → `startupBlock` |
| Captcha | `pkg/captcha` | Already `siteKey` / `secretKey`; do not grow a `bouncer` field |
| Operator YAML | `README.md`, `examples/**` plugin files, `tests/e2e/**` plugin files | Public keys |
| Live catalog | `openspec/specs/core_plugin_*`, `build_e2e_pester_crowdsec-stack` | Fold public names; inherit-timeout SHALL → REMOVED |
| Usage packets | `knowledge/devdocs/core_plugin_*` (consumed) | Stale keys and inherit-timeout How-to |

### Reproduce

This is a rename, not a bug. **Confirmed current:** `pkg/configuration/configuration.go` `Config` JSON tags still use `crowdsec*` / unprefixed names (`enabled`, `httpTimeoutSeconds`, `crowdsecLapiHost`, `crowdsecMode`, `redisCacheEnabled`, `captchaSiteKey`, `streamStartupBlock`, `Crowdsec*` TLS/CAPI fields). `CreateConfig` in `plugin.go` returns `configuration.New()` only. `GetVariable` uses reflect `FieldByName(key+"File")` then `key` — the string is the Go field name.

### Call sites (bounded rows)

`GetVariable` production: **30 named-string calls + 4 prefix-helper calls (34)** in `pkg/**/*.go` excluding `*_test.go`. Roots searched: `pkg` (all `.go`). Files: `pkg/lapi/identity.go` (3), `pkg/lapi/client.go` (4), `pkg/configuration/configuration.go` (16 named + 4 `prefix+"TLSCertificate*"`), `pkg/bouncer/bouncer.go` (3), `pkg/appsec/session.go` (3), `pkg/appsec/client.go` (1). One test: `pkg/configuration/zzz_configuration_test.go` `Test_GetVariable`. Unique keys: `CrowdsecLapiTLSCertificateAuthority|Bouncer|BouncerKey`, `CrowdsecCapiMachineID|Password`, `CrowdsecLapiKey`, `RedisCachePassword`, `CrowdsecAppsecKey`, `CrowdsecAppsecTLSCertificateAuthority|Bouncer|BouncerKey`, `CaptchaGateSecret|SiteKey|SecretKey`, plus helpers `prefix+"TLSCertificateAuthority|Bouncer|BouncerKey"` (`CrowdsecLapi` / `CrowdsecAppsec` today → `Lapi` / `Appsec` + `TLSClientCertificate|TLSClientKey`).

`EffectiveHTTPTimeoutSeconds`: **5 production call sites + 1 definition + dedicated tests**. Roots searched: worktree `*.{go,md}` (product + live specs only; do not migrate `openspec/changes/archive` or other runs' `devstate`). Definition: `pkg/configuration/configuration.go`. Calls: `pkg/lapi/client_http.go`, `pkg/lapi/identity.go`, `pkg/appsec/client_http.go`, `pkg/appsec/session.go`, `pkg/bouncer/bouncer.go`. Tests: `pkg/configuration/zzz_http_timeout_test.go`. Live specs that name inherit/timeout: `core_plugin_middleware_config-validation`, `core_plugin_lapi_connection`, `core_plugin_appsec_client`, `core_plugin_middleware_bouncer`, `core_plugin_lapi_reclaim-key`.

Operator plugin YAML (plugin keys only; not CrowdSec `acquis.yaml`): **11 examples + 12 mock dynamics + 2 real e2e + README + `.traefik.yml`**. Roots searched: `examples/**/*.{yml,yaml}` (`plugin.bouncer` / `plugin:`), `tests/e2e/mock/scenarios/*/dynamic.yml`, `tests/e2e/real`, `README.md`, `.traefik.yml`. Examples: `trusted-ips`, `tls-auth`, `redis-cache`, `standalone-mode`, `kubernetes/traefik/plugin.yml`, `geoenrich-decisions/dynamic.yml`, `custom-captcha`, `custom-ban-page`, `captcha`, `behind-proxy`, `appsec-enabled` (docker-compose or dynamic). `examples/binary-vm` has no plugin keys. Sample old-key grep (`crowdsecLapiHost|httpTimeoutSeconds|crowdsecLapiEnabled|redisCacheEnabled|captchaSiteKey|streamStartupBlock`) hits the mock 12, real `dynamic-scopes.yml` + `docker-compose.test.yml`, `examples/kubernetes/traefik/plugin.yml`, `examples/geoenrich-decisions/dynamic.yml`, `examples/captcha/*`, README, and the consumed usage packets. Other example compose files use more old keys (`crowdsecMode`, `crowdseclapikey` labels, captcha/TLS). `httpTimeoutSeconds: 2` is **not found** in-tree (only `requirement.md` / `ticket/`). Real e2e uses `httpTimeoutSeconds: "60"` (3 middlewares). README sample uses `httpTimeoutSeconds: 10`.

Live specs that name a public / old key (catalog `openspec/specs/**/spec.md` only): **11** — `core_plugin_middleware_config-validation`, `core_plugin_middleware_bouncer`, `core_plugin_lapi_scope-union`, `core_plugin_lapi_reclaim-key`, `core_plugin_lapi_failure-action`, `core_plugin_lapi_connection`, `core_plugin_decisionstore_store`, `core_plugin_appsec_failure-action`, `core_plugin_appsec_client`, `core_plugin_appsec_bot-detection`, `build_e2e_pester_crowdsec-stack`.

Reclaim identity JSON owners: `pkg/lapi/identity.go` (`identity` json `lapiScheme/lapiHost/lapiKey`, `tlsCertificateBouncer`, `httpTimeoutSeconds`, `redisCache*`, `crowdsecCapiScenarios`; `ownership` the same plus middleware name and intervals). AppSec: `pkg/appsec/session.go` (already `scheme/host/path/key`; still `tlsCertificateBouncer`). Reuse those marshalers; do not reconstruct in `configuration` or `bouncer`.

### Language deltas (shown, not written)

Consumed: `knowledge/devdocs/index.md` → `index_core_plugin.md` → `core_plugin_middleware_config-validation.md`, `core_plugin_lapi_connection.md`, `core_plugin_lapi_reclaim-key.md`, `core_plugin_middleware.md`, `core_plugin_appsec.md`. No `priority: always` packets. Attended produce waits. Usage is stale (old keys + inherit timeout) but enough to call the subsystems — not a hard usage gap. Do not write packets in this phase.

Proposed Language (wait for yes / edit / skip):

- **Remove** `EffectiveHTTPTimeoutSeconds` from `core_plugin_middleware_config-validation` (deleted; nothing inherits).
- **Rename** `CrowdsecAppsecEnabled` → **AppsecEnabled** (Config field that means this router will open AppSec).
- **Update** `Two configuration axes`: `lapiEnabled` owns LAPI; `appsecEnabled` owns AppSec; `bouncerEnabled` only bounces. `lapiMode` is the owned LAPI fetch strategy. _Avoid_ still: treating mode as which legs run.
- **Update** Ownership key / SessionHex field names (`lapiStreamScopes`, `lapiCapiScenarios`, `lapiRedisEnabled`, `bouncerStartupBlock`).
- **Add** (optional, skip is valid): **Config domain prefix** — the operator label on `configuration.Config` (Go field and JSON tag). It does not travel past the package that owns the value. _Avoid_: nested YAML, old-key alias, repeating the prefix inside `pkg/lapi` or `pkg/appsec`.

Usage How-to that will move with implement / `opd-devdocsimpact` (not written now): inherit-timeout calls, `GetVariable` string literals, `crowdsecMode: appsec` examples, `streamStartupBlock` on the request path. Stale contradiction left for that later fold: `core_plugin_lapi_connection` still says keep `StreamStartupBlock` write-once at `startStream` and not on Bouncer; live `core_plugin_middleware_bouncer` already places the request-path guard on the bouncer.

### Outside facts

In-tree only. Traefik Yaegi decodes operator YAML/labels onto `Config` via JSON tags. `CreateConfig` does not name fields. No research slug.

## Decisions

- Chosen seam: rename `Config` JSON tags + Go fields; drop prefix at the package boundary (`pkg/lapi` matches AppSec); three timeout knobs `>= 1` default 10; delete `httpTimeoutSeconds` + `EffectiveHTTPTimeoutSeconds`; no aliases; fold live specs (MODIFIED public names / REMOVED inherit timeout); no new spec family.
- Do not commit `docs/config-domain-prefixes.md` into the product tree (not on dest or this worktree; change spec is the record). Requirement "What moves" does not ask to ship that file.
- Rejected: old-key aliases or nested YAML (requirement forbids both).
- Rejected: reconstructing reclaim identity JSON in `configuration` or `bouncer` (owners already exist).
- Rejected: copying AppSec timeout or TLS from LAPI (timeout does not copy; TLS copy is out of scope).
- Rejected: migrating `openspec/changes/archive` or other runs' `devstate`.
- Rejected: renaming CrowdSec protocol constants (`X-Api-Key`, `v1/decisions`, CAPI `machine_id`).
- Live contract: fold existing catalog — `core_plugin_middleware_config-validation`, `core_plugin_middleware_bouncer`, `core_plugin_lapi_connection`, `core_plugin_lapi_reclaim-key`, `core_plugin_lapi_scope-union`, `core_plugin_lapi_failure-action`, `core_plugin_appsec_client`, `core_plugin_appsec_failure-action`, `core_plugin_appsec_bot-detection`, `core_plugin_decisionstore_store`, `build_e2e_pester_crowdsec-stack`. No new spec family.

## Open questions

- Q: Who owns reclaim identity JSON?
  Rank: bounded asked — 2 marshaler types enumerated (`pkg/lapi/identity.go` identity+ownership, `pkg/appsec/session.go`); requirement Boundary names reclaim identity JSON field names and forbids reconstructing table mechanics beyond those names
  Decision: resolved — LAPI owner is `pkg/lapi/identity.go` (`identity` + `ownership`). AppSec owner is `pkg/appsec/session.go`. Reuse those marshalers; drop the redundant `lapi` prefix on LAPI JSON to match AppSec (`scheme`/`host`/`path`/`key`); rename `tlsCertificateBouncer` → `tlsClientCertificate` / `tlsClientKey` on both; Redis/CAPI JSON drop the public `lapi`/`crowdsec` syllables inside the LAPI package. Do not reconstruct the payload in `configuration` or `bouncer`. Hash change = process restart (same break as the public rename). Unmeasured in-process reclaim without restart is out of scope.
  By: explore

- Q: Which string surfaces besides JSON tags still name old fields (CreateConfig / Yaegi / GetVariable / errors / testData)?
  Rank: bounded asked — 34 GetVariable production calls + `CreateConfig` + `.traefik.yml` testData + `ValidateParams` error strings enumerated; requirement Unknowns and "GetVariable strings = new field names" / "What moves"
  Decision: resolved — operator YAML/labels bind JSON tags. `CreateConfig` exposes no names (`return configuration.New()`). `GetVariable` and validation errors use Go field names (new: `LapiKey`, `LapiTLSClientCertificate`, `LapiHTTPTimeoutSeconds`, `cannot be less than 1`). `.traefik.yml` `testData` uses Go field names (`Enabled` → `BouncerEnabled`, `CrowdsecLapiKey` → `LapiKey`). Prefix helpers become `Lapi`/`Appsec` + `TLSCertificateAuthority` / `TLSClientCertificate` / `TLSClientKey`.
  By: explore

- Q: Which live specs fold, and is a new spec family needed?
  Rank: bounded asked — 11 live `openspec/specs/**/spec.md` files name old public keys (roots: `openspec/specs`, not archive); requirement "What moves" + "OpenSpec specs that name a public key"
  Decision: resolved — fold those 11 (MODIFIED public names; REMOVED inherit-timeout SHALL on the timeout owners). No new spec family. Do not migrate `openspec/changes/archive` or other runs' `devstate`.
  By: explore

- Q: Does this change ship `docs/config-domain-prefixes.md` in the product tree?
  Rank: additive incidental — file is absent on dest and this worktree; no In-scope line names shipping it
  Decision: resolved — do not add it. The change spec is the record.
  By: explore

- Q: Which in-tree operator files set `httpTimeoutSeconds: 2` with per-leg overrides at 0?
  Rank: bounded asked — searched worktree `*.{yml,yaml,md}` for `httpTimeoutSeconds: 2`; requirement Timeouts + Unknowns
  Decision: resolved — none in product files. Real e2e uses `60` (set both new knobs to 60). README sample uses `10` (defaults already 10). An external operator who had shared `2` sets `lapiHttpTimeoutSeconds` and `appsecHttpTimeoutSeconds` to 2. No alias.
  By: explore

- Q: Should Language / usage packets be written in explore?
  Rank: bounded asked — 5 consumed packets already document the units; requirement "What moves" names `knowledge/devdocs/`
  Decision: resolved — show Language deltas above; do not write usage or Language in this phase (attended produce waits; no hard gap). Implement / `opd-devdocsimpact` move the packets with the public names.
  By: explore
