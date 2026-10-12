# Nitpicks

1. [hard] Name for the scope — `pkg/modsecurity/inspect.go:119` — `handleSidecarDoError` is named by the mood `handle`; the body classifies inbound cancel vs sidecar miss
   Fix: Rename to the job (`replySidecarDoError`, matching `replyInboundBodyReadFailure`)
   Quote:
      ```
      func (c *Client) handleSidecarDoError(rw http.ResponseWriter, req *http.Request, failMode string, err error) bool {
      	inboundErr := req.Context().Err()
      	if errors.Is(inboundErr, context.Canceled) {
      		c.log.Info("inbound request canceled; WAF call aborted", "error", err, "inbound", inboundErr)
      		http.Error(rw, "", http.StatusBadGateway)
      		return true
      	}
      	c.reportOutcome(false)
      	c.log.Error("fail to send HTTP request to modsec", "error", err, "inbound", inboundErr)
      	return c.serveFailClosed(rw, failMode)
      }
      ```
   Status: open
   Argument: none.
2. [hard] Name for the scope — `pkg/modsecurity/inspect.go:142` — `serveFailClosed` names only close; the body also continues on open
   Fix: Rename to `applyFailMode` (or `serveFailMode`) so the identifier covers both cases
   Quote:
      ```
      func (c *Client) serveFailClosed(rw http.ResponseWriter, failMode string) bool {
      	if configuration.EffectiveModsecFailMode(failMode) == configuration.ModsecFailModeClose {
      		http.Error(rw, "", http.StatusBadGateway)
      		return true
      	}
      	return false
      }
      ```
   Status: open
   Argument: none.
3. [hard] Name for the scope — `pkg/modsecurity/inspect.go:98` — `denyAdmission` names the deny mood; the body also admits (nil gate / allowed) and returns skip vs wrote
   Fix: Rename to the call-site job (`skipSidecarHop` or `admitHop`)
   Quote:
      ```
      func (c *Client) denyAdmission(rw http.ResponseWriter, req *http.Request, failMode string) (skipHop bool, wrote bool) {
      	if c.gate == nil {
      		return false, false
      	}
      	allowed, _, allowErr := c.gate.Allow(req.Context(), gateKey)
      	if allowErr != nil {
      		if errors.Is(allowErr, context.Canceled) || errors.Is(req.Context().Err(), context.Canceled) {
      			c.log.Info("inbound request canceled; WAF call aborted", "error", allowErr, "inbound", req.Context().Err())
      			http.Error(rw, "", http.StatusBadGateway)
      			return true, true
      		}
      		c.log.Error("fail to admit WAF request", "error", allowErr)
      		return true, c.serveFailClosed(rw, failMode)
      	}
      	if !allowed {
      		c.log.Warn("skipping sidecar; waf backoff open")
      		return true, c.serveFailClosed(rw, failMode)
      	}
      	return false, false
      }
      ```
   Status: open
   Argument: none.
4. [hard] Symmetry and consistency — `plugin.go:141` — `openOwned` walks LAPI, AppSec, Captcha, then ModSec; sibling `claimOwned` walks LAPI, AppSec, ModSec, then Captcha
   Fix: Use the same leg order in both (`openOwned`'s LAPI, AppSec, Captcha, ModSec)
   Quote:
      ```
      func openOwned(...) error {
      	// LAPI, AppSec, Captcha, then ModSec
      }
      func claimOwned(...) error {
      	// LAPI, AppSec, ModSec, then Captcha
      }
      ```
   Status: open
   Argument: none.
5. [hard] Symmetry and consistency — `pkg/modsecurity/inspect.go:104` — inbound-cancel in `denyAdmission` ORs `allowErr` with `ctx.Err()`; sibling `handleSidecarDoError` checks only `req.Context().Err()`
   Fix: Use the same cancel detection (and the same empty-502 / log steps) on both paths
   Quote:
      ```
      if errors.Is(allowErr, context.Canceled) || errors.Is(req.Context().Err(), context.Canceled) {
      	c.log.Info("inbound request canceled; WAF call aborted", "error", allowErr, "inbound", req.Context().Err())
      	http.Error(rw, "", http.StatusBadGateway)
      	return true, true
      }
      inboundErr := req.Context().Err()
      if errors.Is(inboundErr, context.Canceled) {
      	c.log.Info("inbound request canceled; WAF call aborted", "error", err, "inbound", inboundErr)
      	http.Error(rw, "", http.StatusBadGateway)
      	return true
      }
      ```
   Status: open
   Argument: none.
6. [hard] Clear conditions — `pkg/modsecurity/body.go:25` — `usePool` / `if !usePool` is the complement of a flag; the body is known ContentLength above `poolCap`
   Fix: Early return `if req.ContentLength >= 0 && req.ContentLength > c.poolCap { return io.ReadAll(req.Body) }`
   Quote:
      ```
      usePool := true
      if req.ContentLength >= 0 {
      	usePool = req.ContentLength <= c.poolCap
      }
      if !usePool {
      	return io.ReadAll(req.Body)
      }
      ```
   Status: open
   Argument: none.
7. [hard] Clear conditions — `pkg/modsecurity/inspect.go:88` — `n > 0 || err == nil` hides "got a readable body byte"
   Fix: `if n > 0` (EOF means no body byte)
   Quote:
      ```
      if n, err := limitedBody.Read(testByte); n > 0 || err == nil {
      	c.log.Warn("HTTP request should not have a body, rejecting", "method", req.Method)
      	http.Error(rw, "HTTP "+req.Method+" requests should not have a body", http.StatusBadRequest)
      	return true
      }
      ```
   Status: open
   Argument: none.
8. [hard] Linear coding — `plugin.go:180` — `claimOwned` inlines "clear already-published legs" as growing `if config.*Enabled { ClearPublisher }` lists on each failure
   Fix: Extract a method named for that job; each claim failure asks it with the legs already claimed
   Quote:
      ```
      if err := claimOwnedLeg(..., config.ModsecEnabled, legModsec); err != nil {
      	if config.LapiEnabled {
      		reclaim.ClearPublisher(name, legLAPI)
      	}
      	if config.AppsecEnabled {
      		reclaim.ClearPublisher(name, legAppSec)
      	}
      	return err
      }
      err := claimOwnedLeg(..., config.CaptchaEnabled, legCaptcha)
      if err != nil {
      	if config.LapiEnabled {
      		reclaim.ClearPublisher(name, legLAPI)
      	}
      	if config.AppsecEnabled {
      		reclaim.ClearPublisher(name, legAppSec)
      	}
      	if config.ModsecEnabled {
      		reclaim.ClearPublisher(name, legModsec)
      	}
      }
      ```
   Status: open
   Argument: none.