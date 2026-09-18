## Context

See proposal.md for motivation. Dest `Validate` accepts siteverify as JSON only via `strings.HasPrefix` on lowercase `application/json`. The inbound captcha form path in the same file already uses `mime.ParseMediaType` (type/subtype case-insensitive, parameters stripped). RFC 9110 § 8.3.1 is in `knowledge/research/ext_http_media-types/`. Cookie mint after a true verify stays on `core_plugin_middleware_captcha-gate`.

## Goals / Non-Goals

**Goals:**
- One owner for the siteverify media-type match: `Validate`.
- Reuse `mime.ParseMediaType`; compare the type token to `application/json`.
- Keep `(false, nil)` and the 200 challenge when the type is missing or not JSON.

**Non-Goals:**
- Inspect siteverify HTTP status (sibling / #52).
- Change inbound form `Content-Type` parsing.
- Change gate cookie format, bind-IP, provider URLs, keys, or the siteverify request body.
- Hunt other `HasPrefix` false-friends as extra cases.

## Decisions

1. **Fix `Validate`, not `ServeHTTP`.** `(false, nil)` is not an error; a ServeHTTP special case would rot next to the shared owner. Alternative: wrap only the challenge handler — rejected, `Validate` is what classifies the provider body.

2. **`mime.ParseMediaType` on the response `Content-Type`.** Compare the returned type token to `application/json`. Go lowercases type/subtype, so equality after parse is the case-insensitive match; parameters are already stripped. Parse error or a different type → today's `responseType:noJson` and `(false, nil)`. Alternative: keep `HasPrefix` plus `EqualFold` — rejected, `application/jsonp` and `;charset=` are not the RFC type token. Alternative: a second EqualFold helper — rejected, this file already owns `mime.ParseMediaType`.

3. **Regression under `pkg/captcha/` with a `zzz_` basename.** Function may keep `TestHunt_siteverifyJSONContentTypeIsCaseInsensitive`. Stub siteverify `Application/JSON` + `{"success":true}` and assert 302 plus `crowdsec_captcha_gate`. Do not copy a hunt worktree file as dest. Alternative: a `Validate`-only unit — rejected, Desired is cookie + 302.

## Risks / Trade-offs

- [Equals-before-parameters rejects `application/jsonp`] → Accepted side effect of the required match, not extra ticket work.
- [Missing `Content-Type` with a JSON body stays `(false, nil)`] → Accepted; Desired is the media-type match only.

## Migration Plan

None. Same binary; mixed-case JSON siteverify starts succeeding.

## Open Questions

None — ticket decisions stand on `devstate/explore.md`.
