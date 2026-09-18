## Context

See `proposal.md` Why. Baseline is `origin/master`. Dest `getToken` interpolates `c.crowdsecMachineID`, `c.crowdsecPassword`, and `strings.Join(c.crowdsecScenarios, `","`)` into a JSON-looking string (`pkg/lapi/client_http.go`). `encoding/json` is already imported here for the login **response**. `Login` is that response DTO. Official CAPI/LAPI login names only `machine_id`, `password`, `scenarios` (`knowledge/research/ext_crowdsec_capi_watchers-login/`).

FindSpecHost:

```
verdicts:
  - { deltaId: capi-login-body-encoding, fold|new: fold, spec-id: core_plugin_lapi_query-round-trip, confidence: high, candidates: [core_plugin_lapi_query-round-trip, core_plugin_lapi_connection] }
```

Search: family `core_plugin_lapi` holds `query-round-trip` (already the owner of the `getToken` / `sendQuery` exchange; login 401 no-recurse is already a scenario there) and `connection` (transport storage; `getToken` writes the token on the stored transport, not the login body). Login-body encoding is one added requirement on that same `getToken` call, not a new leaf.

## Goals / Non-Goals

**Goals:**

- Any legal CAPI credential stored on `Client` yields a login body a JSON decoder can read back as those same strings.
- Empty and nil scenario lists encode as `[]` and `null`, not sprintf’s `[""]`.

**Non-Goals:**

- Changing `sendQuery` headers, renewal, drain, or error wrapping.
- Setting `Content-Type` or `SetEscapeHTML(false)`.
- Accepting a 2xx login body that has a token but omits JSON `code`.
- CAPI v3 `machine_id` length/pattern checks or other config validation.
- Importing the off-tree hunt file or keeping the `TestHunt_` name.

## Decisions

1. **`json.Marshal` of an unexported request struct.** Tags `machine_id`, `password`, `scenarios`. Do not reuse `Login` (that is the response). The request DTO exists only to feed `getToken`, so it may sit next to `Login` in `client_http.go`. Alternative: official-client `json.Encoder` + `SetEscapeHTML(false)` — rejected this ticket; posted fields are compared after decode, and `json.Marshal` is already the package idiom (`session`, `identity`, `metrics`). HTML-escaping `&<>` is acceptable.

2. **Credential owner is `Client`.** `getToken` encodes `c.crowdsecMachineID`, `c.crowdsecPassword`, `c.crowdsecScenarios` only. Those were copied in `New` from `config.CrowdsecCapi*` after `Prepare` `GetVariable`. Do not re-read files or reconstruct identity.

3. **Marshal failure wraps and returns.** `fmt.Errorf("getToken:marshal %w", err)` — same shape as `reportMetrics:marshal`. Do not POST a sprintf fallback. Reaching this branch with three string fields is not expected; still handle it.

4. **Scenarios as-is, no `omitempty`.** Official `WatcherAuthRequest` tags `scenarios` without `omitempty`. CAPI swagger marks the field optional; no evidence it rejects `null`. Do not invent a default scenario.

5. **Regression test `TestGetToken_LoginBodyIsValidJSON`** in `pkg/lapi/zzz_client_http_test.go`. Stub captures the login POST body, unmarshals it, and compares the three fields to Client values that contain `"`, `\`, and a newline. Add cases for empty and nil `crowdsecScenarios`. Do not import the off-tree hunt file.

6. **Usage packet stays caller-facing.** `knowledge/devdocs/core_plugin_lapi_query-round-trip.md` is enough to call `sendQuery` / `getToken`. A marshal gotcha is for the implementer of `getToken`, not a caller. Leave usage for `sbs-dev-devdocsimpact` if that phase finds the packet incomplete after apply. Extend the main spec Purpose in apply so the leaf still names login-body encoding.

## Risks / Trade-offs

- [Nil/empty scenarios change from `[""]` to `null`/`[]`] → Matches official client encoding. Alone-mode configs that omit `crowdsecCapiScenarios` now send `null` instead of one empty string. Accepted; sprintf’s `[""]` was an interpolation artifact, not a documented contract.
- [`json.Marshal` HTML-escapes `&<>`] → A decoder still yields the original string. Official client disables HTML escape as a nicety, not a schema requirement.
- [Encode-failure branch is hard to reach] → Keep the wrap-and-return path for symmetry; do not add a test that tampers with `json.Marshal`.

## Migration Plan

No public JSON/YAML key changes. Rollback is revert.
