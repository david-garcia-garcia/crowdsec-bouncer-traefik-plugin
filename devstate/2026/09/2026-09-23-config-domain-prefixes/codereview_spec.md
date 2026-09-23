# Spec

1. [wrong] LAPI identity Redis JSON — `pkg/lapi/identity.go:27` — `identity` and `ownership` still marshal Redis as `redisCacheEnabled` / `redisCacheHost` / `redisCacheReadHosts` / `redisCachePassword` / `redisCacheDatabase`; `core_plugin_lapi_reclaim-key` Requirement: Reclaim identity JSON reuses the LAPI marshalers names Redis `enabled` / `host` / `readHosts` / `password` / `database`
   Fix: Change those JSON tags on `identity` and `ownership` to `enabled`, `host`, `readHosts`, `password`, and `database`
   Status: done
   Argument: Nested `storeParams` `json:"redis"` on both marshalers (same names as `storeParams`; avoids colliding with LAPI `host`/`key`).
2. [wrong] Transport TLS field names — `pkg/appsec/client_http.go:20` — transport still spells `appsecTLSClientCertificate` (LAPI `pkg/lapi/client_http.go:55` is `lapiTLSClientCertificate`); `core_plugin_appsec_client` Requirement: AppSec identity JSON reuses the session marshaler says transport fields SHALL use `TLSClientCertificate` / `TLSClientKey`, and design drops the domain word on LAPI transport the same way
   Fix: Rename those transport fields to `TLSClientCertificate` (and `TLSClientKey` where the key is stored)
   Status: done
   Argument: LAPI and AppSec transport fields renamed to `TLSClientCertificate`; neither stores the key.
3. [wrong] Removed AppSec block bools — `(spec)` — `core_plugin_appsec_failure-action` Requirement: Three AppSec block booleans are removed only records that `crowdsecAppsecFailureBlock`, `crowdsecAppsecUnreachableBlock`, and `crowdsecAppsecUnreadableBodyBlock` SHALL stay removed
   Fix: Delete that requirement from the change spec
   Status: done
   Argument: Deleted cleanup/absence SHALL from `openspec/changes/config-domain-prefixes/specs/core_plugin_appsec_failure-action/spec.md`.
