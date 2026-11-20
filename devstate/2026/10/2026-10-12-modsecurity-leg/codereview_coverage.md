# Test coverage

1. [hard] Assertion does not prove the job — `pkg/bouncer/bouncer.go:472` — AppSec gate skip must continue; TestServeHTTP_appsecGateSkipStillRunsModsec asserts 403, which is also FailureAction ban
   Quote:
      ```
      if errors.Is(err, appsec.ErrGateSkip) { return false }
      TestServeHTTP_appsecGateSkipStillRunsModsec: status 403, hits==1, no ban:modsec header
      ```
   Fix: Assert skip without ModSec reaches origin 200, or that the 403 sets `X-Remediation` to `ban:modsec`
   Status: done
   Argument: TestServeHTTP_appsecGateSkipStillRunsModsec asserts ban:modsec
2. [hard] Critical path untested — `pkg/modsecurity/inspect.go:112` — gate skip with failMode close must write empty 502; TestInspect_gateSkipUsesFailMode only drives open
   Quote:
      ```
      if !allowed { return true, c.serveFailClosed(rw, failMode) }
      TestInspect_gateSkipUsesFailMode (open only); e2e /modsec-backoff is also fail-open
      ```
   Fix: Assert a tripped-gate inspect with failMode close is empty HTTP 502 and does not call the sidecar
   Status: done
   Argument: TestInspect_gateSkipUsesFailMode now drives close 502
3. [hard] Critical path untested — `pkg/modsecurity/inspect.go:119` — sidecar transport error must follow failMode; tests cover sidecar HTTP 5xx only
   Quote:
      ```
      handleSidecarDoError: non-cancel Do error then reportOutcome(false) then serveFailClosed
      TestInspect_sidecar5xxUsesFailMode (HTTP 5xx); (none) for connection/transport failure
      ```
   Fix: Assert Inspect against an unreachable sidecar continues on open and writes empty 502 on close
   Status: done
   Argument: added TestInspect_sidecarTransportErrorUsesFailMode
4. [hard] Edge case untested — `pkg/modsecurity/inspect.go:121` — inbound cancel must not Report the gate; TestInspect_inboundCancelIsEmpty502 has no gate
   Quote:
      ```
      handleSidecarDoError: Canceled then empty 502, return before reportOutcome
      TestInspect_inboundCancelIsEmpty502: status 502, default backoff 0 so Gate is nil
      ```
   Fix: Cancel inspect with a live gate, then assert a later hop is still admitted
   Status: done
   Argument: added TestInspect_inboundCancelDoesNotTripGate
5. [hard] Edge case untested — `pkg/appsec/query.go:157` — AppSec hop cancel must not Report or apply FailureAction; existing disconnect tests only fail the body read
   Quote:
      ```
      Do err + req.Context() Canceled then ErrClientDisconnected (no reportGate)
      Test_appsecQuery_clientDisconnected: failing Body before the hop, appsecHits==0
      ```
   Fix: Cancel the inbound context during the AppSec hop and assert ErrClientDisconnected with no FailureAction and no gate trip
   Status: done
   Argument: added Test_appsecQuery_hopCancelDoesNotTripGate
6. [hard] Edge case untested — `pkg/modsecurity/inspect.go:23` — deny-verbs 400 must still run after the gate trips; TestInspect_defaultDenyGetWithBody has no gate
   Quote:
      ```
      Inspect: rejectDeniedVerbBody then denyAdmission
      TestInspect_defaultDenyGetWithBody (no gate); (none) after trip
      ```
   Fix: After a tripped gate, assert GET-with-body is still HTTP 400 and failMode is not used
   Status: done
   Argument: added TestInspect_denyGetWithBodyAfterGateTrip
7. [judgement] Happy path only — `pkg/appsec/client.go:122` — AppSec Close closes the Gate; ModSec asserts Report-after-Close, AppSec does not
   Quote:
      ```
      AppSec Client.Close: if gate != nil { gate.Close() }
      TestNew_defaultBackoffBuildsGate (gate != nil); TestNew_positiveBackoffBuildsGateAndCloseClosesIt is ModSec only
      ```
   Fix: After AppSec Client.Close, assert Gate.Report fails
   Status: skipped
   Argument: judgement; not applied unattended
