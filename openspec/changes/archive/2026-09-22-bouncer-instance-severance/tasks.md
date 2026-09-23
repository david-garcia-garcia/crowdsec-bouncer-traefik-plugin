## 1. Configuration and validation

- [x] 1.1 Add `CrowdsecLapiEnabled`, instance name fields, `CrowdsecLapiStreamScopes` to `pkg/configuration`; default LAPI enabled false; drop `appsec` from mode enum.
- [x] 1.2 Prepopulate instance names when leg enabled; AppSec key/scheme copy from LAPI in `Prepare` when AppSec enabled.
- [x] 1.3 Extend `ValidateParams` for E2/E3/E4 and open-vs-subscribe table; remove appsec-mode warn-only path.

## 2. Instance slot layer (`pkg/instance`)

- [x] 2.1 LAPI and AppSec slot tables: Publish, Subscribe, Unsubscribe, Clear (generation-aware), recorded publisher middleware name.
- [x] 2.2 Typed nil stores; mutex covers current pointer and all subscriber Stores; rollback unpublish on rejected multi-leg publish.
- [x] 2.3 Unit tests for collision, rename unpublish on Client, subscriber list leak on bouncer ctx Done.

## 3. Plugin constructor (`plugin.go`)

- [x] 3.1 Child holder context; open owned legs; publish; subscribe when `enabled` and instance name set; fail + cancel on collision.
- [x] 3.2 Wire lifecycle logs (backend + bouncer bound/unbound) per requirement table.
- [x] 3.3 Adjust `zzz_plugin_test.go` / constructor tests.

## 4. LAPI reclaim and stream

- [x] 4.1 Ownership Open key: middleware name + client knobs (intervals, CAPI, defaultDecisionSeconds, scopes, TLS, timeout, Redis block rules).
- [x] 4.2 SessionHex: canonical stream scope list; Redis only when enabled; remove `rejectForeignStoreOwner`.
- [x] 4.3 Stream poll uses opener scopes only; remove `registerLiveHeaderScopes` union path.
- [x] 4.4 Stream collision WARN; Client stores last published slot name for Wake rename unpublish.
- [x] 4.5 Go tests S1–S5, I1–I3; replace named tests in `pkg/lapi/zzz_session_test.go`.

## 5. AppSec reclaim

- [x] 5.1 Include middleware name in Open key; knob change → new Client (no AdoptTransport for timeout/TLS).
- [x] 5.2 Go tests P1–P4 in `pkg/appsec/zzz_session_test.go`.

## 6. Bouncer

- [x] 6.1 Two `atomic.Value` fields; `ServeHTTP` Load only; mode from loaded LAPI client.
- [x] 6.2 Request-path `streamStartupBlock`, backend missing WARN, scope coverage WARN at bind.
- [x] 6.3 Remove client startup block from stream path where spec moves guard to bouncer.

## 7. Documentation and debt

- [x] 7.1 Create `knowledge/debt/2026-09-22-stream-startup-block-rethink.md` and `knowledge/debt/2026-09-22-appsec-tls-follows-lapi.md`.
- [x] 7.2 README severance section (T1–T3, shared owner, placeholder, AppSec-only).

## 8. Real e2e

- [x] 8.1 Writable dynamic config in real harness; add `tests/e2e/real/instance_severance.Tests.ps1`.
- [x] 8.2 Implement T/L/R/N/F/C/E cases from requirement matrix; DEBUG log level for lifecycle cases.

## 9. Devdocs (implement / devdocsimpact)

- [x] 9.1 Update `core_plugin_middleware.md`, `core_plugin_lapi_reclaim-key.md`, `core_plugin_lapi_scope-union.md`; add usage for `pkg/instance` if new packet warranted.
