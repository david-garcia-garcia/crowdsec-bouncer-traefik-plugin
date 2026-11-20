# Standards

1. [hard] Leave a trail — `README.md:507` — trusted-IP skip now includes ModSec, but the LAN/VPN section still says AppSec only
   Fix: Say trusted client IPs skip LAPI, AppSec, and ModSec, matching ServeHTTP and the BouncerClientTrustedIPs variable text
   Status: done
   Quote:
      ```
      `bouncerClientTrustedIps` lets these client addresses skip all checks, AppSec included. See [examples/trusted-ips](examples/trusted-ips/README.md).
      ```
   Argument: README LAN/VPN skip now names LAPI, AppSec, and ModSec
2. [hard] Leave a trail — `README.md:877` — ReclaimGraceSeconds still names only LAPI and AppSec after ModSec Open uses the same reclaim table
   Fix: Name ModSec with LAPI and AppSec on that variable
   Status: done
   Quote:
      ```
      **ReclaimGraceSeconds** (int64, default `30`)
      How long a LAPI or AppSec connection stays open after no middleware uses it, so a Traefik config reload can reuse it instead of reconnecting.
      ```
   Argument: ReclaimGraceSeconds now names LAPI, AppSec, and ModSec
3. [hard] Leave a trail — `pkg/appsec/client.go:110` — Close now shuts the admission gate, but the comment still says idle HTTP only
   Fix: Match the ModSec Close comment: release the gate and idle HTTP
   Status: done
   Quote:
      ```
      // Close releases idle AppSec HTTP connections. Safe to call more than once.
      func (c *Client) Close() {
      	...
      	if gate != nil {
      		gate.Close()
      	}
      ```
   Argument: AppSec Close comment now matches ModSec (gate and idle HTTP)
4. [hard] Leave a trail — `pkg/modsecurity/inspect.go:159` — sidecar body drain collapses copy errors to `_`; AppSec `drainResponse` keeps them at Debug
   Fix: Log the copy error at Debug with a drain stem, same as `appsecQuery:drainBody`
   Status: done
   Quote:
      ```
      func discardSidecarBody(body io.Reader) {
      	_, _ = io.Copy(io.Discard, io.LimitReader(body, sidecarBodyDrainLimit))
      }
      ```
   Argument: discardSidecarBody logs drain errors at Debug as modsecInspect:drainBody
5. [judgement] Duplicated Code — `pkg/modsecurity/gate.go:14` — `newAdmissionGate` is a near-copy of `pkg/appsec/gate.go`; period/max/threshold/ratio mapping already diverged on a `trip` local
   Fix: One owner that maps those four knobs onto `backendbackoff.Config` and call it from both Clients
   Status: skipped
   Quote:
      ```
      func newAdmissionGate(period, maxPeriod, threshold int64, ratio float64) (*backendbackoff.Gate, error) {
      	if period <= 0 {
      		return nil, nil //nolint:nilnil // omitted backoff means no gate
      	}
      ```
   Argument: judgement; not applied unattended
6. [hard] Bound the ask — `knowledge/opendev.json:18` — `model_opd-redflags` is unrelated catalog work on the ModSec change
   Fix: Drop it from this diff; land the catalog key on its own change
   Status: done
   Quote:
      ```
      "model_opd-pullrequest": "",
      "model_opd-redflags": "",
      "model_opd-refine": "",
      ```
   Argument: dropped model_opd-redflags from this change's knowledge/opendev.json