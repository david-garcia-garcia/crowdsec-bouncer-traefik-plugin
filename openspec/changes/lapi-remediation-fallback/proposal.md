# Proposal

## Why

Since fork PR #198 (https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/198) every LAPI decision type that is neither `ban` nor `captcha` stores and applies as ban, with no operator choice. That followed upstream issue #402 point 1 (https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/402) and upstream PR #403 point 1 (https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403). The CrowdSec bouncer spec defines a `remediation_fallback` (ignore / ban / captcha) for exactly this case, and today an unknown-type `deleted` row can clear a ban that another decision holds on the same value.

Upstream PR #433 (https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/433) proposes treating `whitelist` decisions as an allow. This change rejects that model: `whitelist` and `allow` are not valid CrowdSec decision types, and using decisions to allow traffic is an inadequate way to manage whitelists, because the LAPI stream is designed to say WHAT TO BLOCK, not WHAT TO ALLOW. Allowing traffic is done upstream by parser whitelists and LAPI allowlists (`cscli allowlists`), which stop or expire decisions at the source.

## What Changes

- New public config `lapiRemediationFallback` (Go `LapiRemediationFallback`): `ban` | `captcha` | `ignore`, default `ban` (keeps #198 behavior). Empty is `ban`. Any other value fails `ValidateParams`.
- It applies only to LAPI decision types that are neither `ban` nor `captcha`, at LAPI ingest (stream Ip, header-mapped scopes, Range; live; none). `ban` and `captcha` stay as today.
- `ban` / `captcha`: the unknown type stores as that kind. Stream `deleted` keeps today's whole-slot / whole-CIDR delete.
- `ignore`: the unknown type is not stored on stream `new` (Ip, header scope, Range), a stream `deleted` row of that type deletes nothing (Ip, header scope, Range), and live/none never pick it; an IP whose only decisions are unknown-type passes.
- No type name is special-cased in code (`whitelist`, `allow`, `throttle`, … all follow the one knob).
- The knob is set on the middleware that opens the LAPI connection (opener-only, like `lapiStreamScopes`). It enters the LAPI ownership key and, only when not `ban`, `SessionHex`, so a change opens a new Client and a new DecisionStore; default deployments keep their store and Redis keys.
- It is not the LAPI-unreachable behavior; that stays `bouncerLapiFailureAction`.
- README and usage docs state the whitelist / allow position with the upstream references. The debt note `knowledge/debt/2026-09-19-multiple-decisions-per-cache-key.md` loses its allow-as-veto framing and recovered "Allow is a whitelist" Pester test; the real multi-decision debt stays.
- Tests and spec scenarios use `throttle` (documented by `cscli decisions add --type`) instead of `allow` as the sample unknown type.

## Capabilities

### New Capabilities

- `core_plugin_lapi_remediation-fallback`: the `lapiRemediationFallback` knob — values, default, validation, opener-only ownership, and what each value does to unknown LAPI types on stream `new`, stream `deleted`, and live/none.

### Modified Capabilities

- `core_plugin_lapi_origin-based-decision-remap`: "Origin remap is one hop at Bouncer apply" and "Live strongest pick uses LAPI type" stop saying an unknown type is always ban; they defer to `core_plugin_lapi_remediation-fallback` (default ban). Sample type `allow` becomes `throttle`.
- `core_plugin_decisions_scopes`: "Ban wins across scopes" — an unknown type follows `lapiRemediationFallback` (default ban) instead of always ban.
- `core_plugin_lapi_reclaim-key`: "Stream session is LAPI URL plus bouncer key" — `lapiRemediationFallback` joins the ownership key and, when not `ban`, `SessionHex`.

## Impact

- `pkg/configuration/configuration.go` (field, constants, default, effective-value helper, validation) and its tests.
- `pkg/lapi/client.go` (`New` reads the knob onto `Client`), `pkg/lapi/client_decisions.go` (ingest kind, stream put/delete items, live pick), `pkg/lapi/client_stream.go` (Range New / Deleted branches), `pkg/lapi/session.go`, `pkg/lapi/identity.go`, and `pkg/lapi` tests.
- `README.md` (Variables entry, Decisions paragraph, distinction from `bouncerLapiFailureAction`).
- `knowledge/devdocs/core_plugin_lapi_stream-apply.md`, `knowledge/devdocs/core_plugin_lapi_origin-based-decision-remap.md`, `knowledge/devdocs/core_plugin_lapi_reclaim-key.md`, `knowledge/devdocs/build_e2e_real.md`.
- `knowledge/debt/2026-09-19-multiple-decisions-per-cache-key.md`.
- No change to `RemediationValue`, `bouncerOriginBasedDecisionRemap`, `bouncerLapiFailureAction`, or the TRACE stem `handleStreamCache:unknownType`.
