## Context

See proposal.md Why. `ValidateParams` already owns AppSec URL, key-file existence, and HTTPS CA PEM through `validateAppsecURLKeyAndTLS`. Live/stream/none/appsec always call it via `validateLapiAndAppsecConnection`. Alone checks CAPI machine id and password, then skips the helper. `appsec.Prepare` owns secret copy and scheme fallback after validation; do not re-derive those checks there. Default AppSec host is `crowdsec:7422`.

## Goals / Non-Goals

**Goals:**
- After CAPI `GetVariable` on machine id and password, call `validateAppsecURLKeyAndTLS` in the alone branch.
- Keep skipping LAPI URL, LAPI key, and LAPI TLS.
- Prove invalid AppSec CA and missing AppSec key file fail in alone; existing alone+CAPI still passes.

**Non-Goals:**
- An enabled-or-fields predicate around the helper.
- Calling `validateLapiAndAppsecConnection` or `validateLapiURLAndKeys` in alone.
- Changing the helper’s explicit-scheme CA trigger (`CrowdsecAppsecScheme == https`).
- AppSec client-cert parse at ValidateParams, Prepare / Open / reclaim / failure-action, live/stream rewrite.

## Decisions

1. Always call `validateAppsecURLKeyAndTLS` after CAPI checks. Spec AppSec URL/CA are not mode-scoped; live/stream already always-on; a gate would leave alone+disabled+bad-host passing while siblings fail. Alternative (ticket’s enabled-or-fields gate) rejected.
2. Reuse the existing helper. It owns URL, `GetVariable("CrowdsecAppsecKey")` (so a set `CrowdsecAppsecKeyFile` must exist), and HTTPS CA PEM. Do not copy those checks into the alone branch or into `appsec.Prepare`.
3. Tests are new `Test_ValidateParams` table rows in `pkg/configuration/zzz_configuration_test.go`. Do not require hunt function name `TestHunt_ValidateParams_aloneModeStillRejectsInvalidAppsecCA`.
4. CA trigger stays `CrowdsecAppsecScheme == https` (not `effectiveAppsecScheme`). Changing it would rewrite live/stream validation.

## Risks / Trade-offs

- Always-on AppSec URL check in alone rejects a bad default host even when AppSec is off. Accepted: same as live/stream; default `crowdsec:7422` already passes the existing "Alone mode with CAPI credentials" row.
- Empty AppSec key is still allowed here; `appsec.Prepare` later copies `CrowdsecLapiKey` (often empty in alone). Out of scope.

## Migration Plan

None. Valid alone+CAPI configs keep starting. Invalid AppSec URL, key file, or HTTPS CA that already fail in live/stream now fail in alone too.

## Open Questions

None — explore decisions stand.
