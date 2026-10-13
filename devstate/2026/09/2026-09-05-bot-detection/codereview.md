# Code review
Pin: origin/master (fef35068)

## Standards
1. [hard] Consume before produce — `pkg/crowdsecconnection/test_appsec_connection.go:10` — `NewTestAppsecConnection` duplicated `appsecConn` in `appsec_test.go`
   → Export one helper; `appsecConn` now calls `NewTestAppsecConnection` and sets `appsecBodyLimit`
2. [judgement] Mysterious Name — `pkg/bouncer/bouncer.go:256` — `decision` holds `*AppsecResponse`
   → Rename to `appsecEnvelope`
3. [judgement] Leave a trail — `pkg/bouncer/bouncer.go:320` — write-failure warn omits IP and action
   → Include `remoteIP` and action on the warn

## Spec
1. [wrong] Structured AppSec JSON — empty/non-action HTTP 200 SHALL pass (nil result, nil error) vs `appsecAllow()`
   → Spec updated: nil error and allow action (golangci `nilnil` forbids `(nil, nil)`)
2. [wrong] Challenge relay — `action: captcha` went to LAPI captcha instead of AppSec envelope
   → Removed the captcha special case; non-allow non-ban relays
3. [wrong] Real stack challenge backend port 7422 vs product 7423
   → Spec/design updated to 7423 (CRS stays on 7422)
4. [missing] tasks.md 1.2 empty 200 unit test
   → `Test_appsecQuery_emptyOKPasses`

## Security
none

## Performance
none

Standards: 3 findings, worst: Consume before produce at `pkg/crowdsecconnection/test_appsec_connection.go:10`
Spec: 4 findings, worst: captcha routed to LAPI instead of relay
Security: 0 findings, worst: none
Performance: 0 findings, worst: none

## Applied
- Standards 1: `appsecConn` calls `NewTestAppsecConnection`; helper sets `appsecBodyLimit`
- Spec 1: SHALL now says allow action, not nil result
- Spec 2: dropped AppSec `captcha` → LAPI captcha branch
- Spec 3: e2e spec and design say port 7423
- Spec 4: `Test_appsecQuery_emptyOKPasses`

## Recorded and skipped
- Standards 2: judgement rename of `decision`
- Standards 3: judgement extra log fields
