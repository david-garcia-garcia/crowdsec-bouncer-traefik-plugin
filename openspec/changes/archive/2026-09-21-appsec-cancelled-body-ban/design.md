## Context

See `proposal.md` — Why. Today `io.ReadAll` on the tee/limit path in `newAppsecBodyRequest` wraps any error as `appsecQuery:GetBody` and bypasses `resultForFailureActionErr`. Other AppSec fallbacks (500, unreachable, unreadable H2/H3 without Content-Length, AppSec response-body io) already use `Policy.FailureAction` at `Query` time. Explore reproduced #395 on this fork: `FailureAction: passthrough` still yields a ban via `applyAppsecServeHTTP`.

## Goals / Non-Goals

**Goals:**

- Honor `crowdsecAppsecFailureAction` when buffering a forwardable body fails because the client left (`errors.Is` for `context.Canceled`, `context.DeadlineExceeded`, `io.ErrUnexpectedEOF`).
- Use a dedicated operator-visible message prefix (e.g. `appsecQuery:clientBodyDropped`) when routing through failure action, distinct from `appsecQuery:GetBody` for unclassified read faults.
- Ship a table-driven test in `pkg/appsec/zzz_query_test.go` that asserts current broken behavior then the fixed contract.

**Non-Goals:**

- New config keys or extending `isBodyUnreadable` to cover mid-read cancel on CL-known requests.
- Optimizing `handleBanServeHTTP` when the client is already disconnected.
- End-to-end HTTP/2 reproduction in CI; unit-test the `Query` / body-build seam.

## Decisions

FindSpecHost (propose):

```yaml
verdicts:
  - { deltaId: client-body-dropped-during-buffer, fold|new: fold, spec-id: core_plugin_appsec_failure-action, confidence: high, candidates: [core_plugin_appsec_failure-action, core_plugin_appsec_client] }
```

1. **Seam: `newAppsecBodyRequest` after `io.ReadAll` error** — Classify client-gone with `errors.Is`, then `return nil, resultForFailureActionErr(pol.FailureAction, "appsecQuery:clientBodyDropped")` (exact string TBD in implement). Unclassified errors keep `fmt.Errorf("appsecQuery:GetBody %w", err)` so they still ban. *Rejected:* always allow on any read error (ignores `ban`/`captcha`). *Rejected:* new knob.

2. **Client-gone set** — `context.Canceled`, `context.DeadlineExceeded`, `io.ErrUnexpectedEOF` only until Traefik-specific evidence adds more. *Rejected:* treating all `GetBody` errors as failure-action (masks genuine faults).

3. **Passthrough semantics** — `resultForFailureAction` allow path means AppSec `Do` is not reached (same as unreachable passthrough returning allow from `Query`). *Not* headers-only GET (that is the unreadable-body passthrough shape).

4. **Bouncer** — No change expected: `applyAppsecServeHTTP` already maps non-`ErrFailureCaptcha` errors to ban; passthrough allow returns nil error from `Query`.

5. **Test strategy** — Implement TDD: subtest documents pre-fix `GetBody` error + ban-equivalent error from `Query` with passthrough; after fix, passthrough returns allow and httptest AppSec server request count stays zero. Reference upstream #395 in test comment.

## Risks / Trade-offs

- **[Risk]** Unclassified read errors still ban → **Mitigation:** keep today’s path; only client-gone types move to failure action.
- **[Risk]** Operators expect headers-only AppSec query on disconnect → **Mitigation:** explore explicitly chose allow-without-AppSec for passthrough; spec scenarios encode that.
- **[Trade-off]** `UnexpectedEOF` may include some server-side closes → accepted per #395 and explore; narrow later if evidence appears.
