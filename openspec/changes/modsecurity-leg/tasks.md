## 1. Configuration and validation

- [ ] 1.1 Add own-axis `modsecEnabled` (default false) and `modsecInstanceName` plus owner-read `modsecUrl`, `modsecHttpTimeoutSeconds`, `modsecBodyLimit` (default 8388608, `0` unlimited), `modsecDenyVerbsWithBody`, and ModSec backoff knobs (period default 0). Per-router `bouncerModsecFailMode` (`open` default). Do not accept `modSecurityUrl`.
- [ ] 1.2 Add AppSec Client backoff knobs: `appsecUnhealthyBackOffPeriodSecs` default 30 (`0` disables), max period, threshold default 5, ratio. Include them in the AppSec ownership key.
- [ ] 1.3 Extend `validateLegOpenVsSubscribe` to ModSec (E2 leftover `modsecInstanceName`; E3 bounce with own off and empty name). Reject enabled ModSec without absolute `http`/`https` `modsecUrl`. Validate failMode and backoff knobs.
- [ ] 1.4 Add action token `bypassModsec`. `bypass` sets SkipModsec. Update `pkg/httprule/action.go` and `zzz_*` token tests.
- [ ] 1.5 Update `zzz_configuration_test.go` (owner vs subscriber, E2/E3 ModSec, failMode, AppSec backoff default 30, body-limit zero unlimited, source camelCase ignored).

## 2. ModSec client (`pkg/modsecurity`)

- [ ] 2.1 Create `pkg/modsecurity` by absorbing source `@e860d249` inspect, body, deny-verbs, and gate wiring. Dest names and Config stems. Do not import `pkg/appsec`.
- [ ] 2.2 `Prepare` fills empty `modsecInstanceName` only when `modsecEnabled`. Ownership key = middleware name plus sidecar knobs listed in 1.1. Open + Close the Gate.
- [ ] 2.3 HTTP client `CheckRedirect` → `http.ErrUseLastResponse`. Copy Host from inbound `req.Host`. Do not set `X-Real-IP`. Do not append `RemoteAddr` to XFF.
- [ ] 2.4 Classify sidecar 2xx allow, 3xx/4xx copy block (omit hop-by-hop + `Server`), 5xx / transport → failMode. Inbound cancel → empty 502, no Report.
- [ ] 2.5 Import `backendbackoff.Gate` from utilities `v1.0.7` (vendor). Gate skip uses failMode. Deny-verbs and body-limit run before Allow.
- [ ] 2.6 Absorb source `zzz_*` unit tests that do not need Docker. Add dest-shaped tests for fill-name, ownership key, zero body unlimited, default deny list vs empty list.

## 3. AppSec admission gate

- [ ] 3.1 Build a Gate on `appsec.Client` when backoff seconds > 0. Close it on Client Close. Query: Allow then hop; Report success on usable verdict; Report failure on transport / 5xx / unreachable; inbound cancel does not Report.
- [ ] 3.2 Gate skip does not call AppSec and does not apply FailureAction. Admitted misses still use FailureAction (default `ban`).
- [ ] 3.3 Update `pkg/appsec` tests for skip-vs-admitted, default 30, `0` disables, ownership key includes backoff knobs.

## 4. Plugin constructor (`plugin.go`)

- [ ] 4.1 Add `legModsec`. Call `modsecurity.Prepare` after captcha Prepare. Add ModSec cases to `openOwned` / `claimOwned` (do not rewrite into an N-leg registry). Multi-leg rollback includes this group (captcha-claim failure also `ClearPublisher` modsec).
- [ ] 4.2 `subscribeModsec = bouncerEnabled && modsecInstanceName != ""`. Pass it to `bouncer.New`. `Watch` `alias:modsec:<name>` after New.
- [ ] 4.3 Update `zzz_plugin_test.go` for owner, subscriber, holder-with-bounce-off, collision, and captcha-claim rollback of ModSec.

## 5. Bouncer

- [ ] 5.1 Add ModSec `atomic.Value`, `ReceiveModSec`, and `subscribeModsec`. `ServeHTTP`: after LAPI and AppSec and captcha write, run ModSec. AppSec gate skip continues to ModSec.
- [ ] 5.2 Missing subscribed ModSec uses `bouncerModsecFailMode`. Action-rule skip skips inspect. Copied 3xx/4xx sets remediation header `ban:modsec` when configured. 413/400 and failMode close 502 omit that header.
- [ ] 5.3 Update `pkg/bouncer/zzz_*.go` for order, skip, missing client, header, and AppSec-skip-then-ModSec.

## 6. Operator files and e2e

- [ ] 6.1 README: whole-project capabilities including ModSec config table and how it works. Remove `traefik-modsecurity` from Traefik Security. Name AppSec skip-after-trip and `appsecUnhealthyBackOffPeriodSecs: 0` to keep per-request FailureAction. Leave Geoblock and Rate Limit.
- [ ] 6.2 Add Pester domain `modsec` to `PesterDomains.ps1` and `.github/workflows/e2e.yml` matrix. `Assert-PesterDomainPartition` must list every `*.Tests.ps1`.
- [ ] 6.3 Compose: inspect-only Apache CRS sidecar. Routes for allow, CRS `../etc`, body-size 413, deny GET-with-body, failMode open/close, backoff skip, action-rule skip. Nginx-drain only if the same harness can switch. Do not port bombardier.
- [ ] 6.4 Add `tests/e2e/real/modsec*.Tests.ps1` covering 6.3. Identify the client only with `X-Forwarded-For`.

## 7. Devdocs (implement / devdocsimpact)

- [ ] 7.1 Leave Language/usage folds for implement / `opd-devdocsimpact` (Bouncer fourth binding, Slot fourth group, Two configuration axes, Action rule tokens, AppSec gate, new ModSec packets). Do not write packets in propose.
