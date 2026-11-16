## 1. Configuration and validation

- [x] 1.1 Add own-axis `modsecEnabled` (default false) and `modsecInstanceName` plus owner-read `modsecUrl`, `modsecHttpTimeoutSeconds`, `modsecBodyLimit` (default 8388608, at least 1 when owned), and `modsecUnhealthyBackOffPeriodSecs` (default 0). Per-router `bouncerModsecFailureAction` (`passthrough` default, `ban`, `captcha`). Do not accept `modSecurityUrl`.
- [x] 1.2 Add `appsecUnhealthyBackOffPeriodSecs` default 30 (`0` disables), the only AppSec backoff knob. Include it in the AppSec ownership key. Fix the trip rule in `pkg/admission` (`TripFailures` 5, `FailureRatio` 0.30, cooldown max = base).
- [x] 1.3 Extend `validateLegOpenVsSubscribe` to ModSec (E2 leftover `modsecInstanceName`; E3 bounce with own off and empty name). Reject enabled ModSec without absolute `http`/`https` `modsecUrl`. Reject `modsecBodyLimit` below 1 when ModSec is owned. Validate `bouncerModsecFailureAction` with `validateFailureAction`. Put both backoff periods in `requiredInt0`.
- [x] 1.4 Add action token `bypassModsec`. `bypass` sets SkipModsec. Update `pkg/httprule/action.go` and `zzz_*` token tests.
- [x] 1.5 Update `zzz_configuration_test.go` (owner vs subscriber, E2/E3 ModSec, failure action including old `open` rejected and captcha without an instance, AppSec backoff default 30, negative ModSec backoff, body-limit zero rejected on the owner and ignored without ModSec, source camelCase ignored).

## 2. ModSec client (`pkg/modsecurity`)

- [x] 2.1 Create `pkg/modsecurity` by absorbing source `@e860d249` inspect, body, and gate wiring (not deny-verbs). Dest names and Config stems. Do not import `pkg/appsec`.
- [x] 2.2 `Prepare` fills empty `modsecInstanceName` only when `modsecEnabled`. Ownership key = middleware name plus sidecar knobs listed in 1.1. Open + Close the Gate.
- [x] 2.3 HTTP client `CheckRedirect` → `http.ErrUseLastResponse`. Copy Host from inbound `req.Host`. Do not set `X-Real-IP`. Do not append `RemoteAddr` to XFF.
- [x] 2.4 `Inspect(req, failureAction)` returns, never writes: 2xx `nil, nil`; 3xx/4xx the response (`WriteBlock` omits hop-by-hop + `Server`); 5xx / transport → `ErrUnavailable` with one debounced ERROR `crowdsec modsec sidecar unavailable` per 5 s. Inbound cancel → `wafhop.ErrClientDisconnected`, no Record.
- [x] 2.5 Import `backendbackoff.Gate` from utilities `v1.0.7` (vendor). Gate skip returns `ErrGateSkip` (continue, no failure action). Body read and body-limit run before Admit.
- [x] 2.6 Absorb source `zzz_*` unit tests that do not need Docker. Add dest-shaped tests for fill-name, ownership key, GET body reaching the sidecar, the streamed-body rule per failure action, and `WriteBlock`.

## 3. AppSec admission gate

- [x] 3.1 Build a Gate on `appsec.Client` when backoff seconds > 0. Close it on Client Close. Query: Allow then hop; Report success on usable verdict; Report failure on transport / 5xx / unreachable; inbound cancel does not Report.
- [x] 3.2 Gate skip does not call AppSec and does not apply FailureAction. Admitted misses still use FailureAction (default `ban`).
- [x] 3.3 Update `pkg/appsec` tests for skip-vs-admitted, default 30, `0` disables, ownership key includes backoff knobs.

## 4. Plugin constructor (`plugin.go`)

- [x] 4.1 Add `legModsec`. Call `modsecurity.Prepare` after captcha Prepare. Add ModSec cases to `openOwned` / `claimOwned` (do not rewrite into an N-leg registry). Multi-leg rollback includes this group (captcha-claim failure also `ClearPublisher` modsec).
- [x] 4.2 `subscribeModsec = bouncerEnabled && modsecInstanceName != ""`. Pass it to `bouncer.New`. `Watch` `alias:modsec:<name>` after New.
- [x] 4.3 Update `zzz_plugin_test.go` for owner, subscriber, holder-with-bounce-off, collision, and captcha-claim rollback of ModSec.

## 5. Bouncer

- [x] 5.1 Add ModSec `atomic.Value`, `ReceiveModSec`, and `subscribeModsec`. `ServeHTTP`: after LAPI and AppSec and captcha write, run ModSec. AppSec gate skip continues to ModSec.
- [x] 5.2 Missing subscribed ModSec and `ErrUnavailable` use `bouncerModsecFailureAction` (`ban`: ban template, reason `MODSEC`, `ban:modsec-failure`, origin `plugin:modsec_failure`; `captcha`: `captcha:modsec-failure`). Gate skip continues. Action-rule skip skips inspect. Copied 3xx/4xx sets remediation header `ban:modsec` when configured and records a dropped request (origin `modsec`). 413 omits that header.
- [x] 5.3 Update `pkg/bouncer/zzz_*.go` for order, skip, missing client, failure actions, ModSec gate skip without failure action, header, and AppSec-skip-then-ModSec.

## 6. Operator files and e2e

- [x] 6.1 README: whole-project capabilities including ModSec config table and how it works. Remove `traefik-modsecurity` from Traefik Security. Name AppSec skip-after-trip and `appsecUnhealthyBackOffPeriodSecs: 0` to keep per-request FailureAction. Leave Geoblock and Rate Limit.
- [x] 6.2 Add Pester domain `modsec` to `PesterDomains.ps1` and `.github/workflows/e2e.yml` matrix. `Assert-PesterDomainPartition` must list every `*.Tests.ps1`.
- [x] 6.3 Compose: inspect-only Apache CRS sidecars `waf` and `waf-flaky`, AppSec proxy `appsec-flaky`, AppSec listener 7424 (`e2e/dual-vpatch`). Routes for allow, CRS `../etc`, GET body (CRS 920170), body-size 413, the three failure actions, WebSocket, action-rule skip (`modsec.yml`); AppSec and ModSec on one router (`waf-dual.yml`); both gates (`waf-backoff.yml`). Nginx-drain only if the same harness can switch. Do not port bombardier.
- [x] 6.4 Add `modsec.Tests.ps1`, `waf_dual.Tests.ps1`, and `waf_backoff.Tests.ps1` covering 6.3; move the AppSec default-gate case from `appsec_backoff.Tests.ps1` into `waf_backoff.Tests.ps1`. Identify the client only with `X-Forwarded-For`.
- [x] 6.5 Add runnable example `examples/modsecurity` (`make run_modsecurity`).

## 7. Devdocs (implement / devdocsimpact)

- [x] 7.1 Leave Language/usage folds for implement / `opd-devdocsimpact` (Bouncer fourth binding, Slot fourth group, Two configuration axes, Action rule tokens, AppSec gate, new ModSec packets). Do not write packets in propose.
