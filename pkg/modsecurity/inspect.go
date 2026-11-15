package modsecurity

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/wafhop"
)

const sidecarBodyDrainLimit = 256 << 10

const headerReasonModsec = "modsec"

// Inspect copies req to the CRS sidecar and classifies the status.
// failMode is per-router open|close. remediationHeader is the optional ban:modsec name.
// True means the response was written. False with a nil error means the caller continues to next.
// wafhop.ErrClientDisconnected and wafhop.ErrClientBodyRead come back unwritten: the bouncer answers
// them the same way for every WAF leg.
func (c *Client) Inspect(rw http.ResponseWriter, req *http.Request, failMode, remediationHeader string) (bool, error) {
	if c.rejectDeniedVerbBody(rw, req) {
		return true, nil
	}
	var body []byte
	switch {
	case wafhop.IsBodyUnreadable(req):
		// Same rule as AppSec: a streamed HTTP/2 or HTTP/3 body is never buffered. On a body method
		// the sidecar cannot see the body, so that is a WAF failure (failMode); otherwise inspect headers only.
		if wafhop.IsMethodWithBody(req.Method) && ApplyFailMode(rw, failMode) {
			c.log.Debug("modsecInspect:unreadableBody dropped", "method", req.Method)
			return true, nil
		}
	case wafhop.HasBody(req):
		read, err := wafhop.ReadBody(req, c.bodyLimit, wafhop.RejectOverLimit)
		if errors.Is(err, wafhop.ErrBodyTooLarge) {
			c.log.Warn("request body too large", "maxBodySizeBytes", c.bodyLimit)
			http.Error(rw, "Request body too large", http.StatusRequestEntityTooLarge)
			return true, nil
		}
		if err != nil {
			return false, err
		}
		body = read
	}

	ticket, admitErr := c.gate.Admit(req.Context())
	if admitErr != nil {
		if wafhop.IsInboundCanceled(req, admitErr) {
			return false, wafhop.ErrClientDisconnected
		}
		c.log.Error("fail to admit WAF request", "error", admitErr)
		return ApplyFailMode(rw, failMode), nil
	}
	if !ticket.Admitted {
		return ApplyFailMode(rw, failMode), nil
	}

	proxyReq, err := http.NewRequestWithContext(req.Context(), req.Method, c.modsecURL+req.URL.RequestURI(), bytes.NewReader(body))
	if err != nil {
		c.log.Error("fail to prepare forwarded request", "error", err)
		http.Error(rw, "", http.StatusBadGateway)
		return true, nil
	}
	// The sidecar sees the end-to-end request. Hop-by-hop headers belong to the client connection,
	// and Content-Length is rebuilt from the bytes forwarded.
	wafhop.CopyEndToEndHeaders(proxyReq.Header, req.Header, "Content-Length")
	proxyReq.Host = req.Host

	resp, err := c.httpClient.Do(proxyReq)
	if err != nil {
		if wafhop.IsInboundCanceled(req, err) {
			return false, wafhop.ErrClientDisconnected
		}
		c.gate.Record(ticket, false)
		c.log.Error("fail to send HTTP request to modsec", "host", sidecarLogHost(c.modsecURL))
		return ApplyFailMode(rw, failMode), nil
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			c.log.Error("fail to close WAF response body", "error", closeErr)
		}
	}()

	if resp.StatusCode >= 300 && resp.StatusCode < 500 {
		c.gate.Record(ticket, true)
		if remediationHeader != "" {
			rw.Header().Set(remediationHeader, "ban:"+headerReasonModsec)
		}
		forwardResponse(resp, rw)
		c.discardSidecarBody(resp.Body)
		return true, nil
	}
	c.discardSidecarBody(resp.Body)
	if resp.StatusCode >= 500 {
		c.gate.Record(ticket, false)
		c.log.Error("fail to send HTTP request to modsec", "error", fmt.Errorf("waf status %d", resp.StatusCode))
		return ApplyFailMode(rw, failMode), nil
	}
	c.gate.Record(ticket, true)
	return false, nil
}

// rejectDeniedVerbBody writes HTTP 400 when a listed method carries a readable body byte.
func (c *Client) rejectDeniedVerbBody(rw http.ResponseWriter, req *http.Request) bool {
	if !c.denyVerbsWithBody[req.Method] || !wafhop.HasBody(req) {
		return false
	}
	limitedBody := http.MaxBytesReader(rw, req.Body, 1)
	testByte := make([]byte, 1)
	if n, _ := limitedBody.Read(testByte); n > 0 {
		c.log.Warn("HTTP request should not have a body, rejecting", "method", req.Method)
		http.Error(rw, "HTTP "+req.Method+" requests should not have a body", http.StatusBadRequest)
		return true
	}
	return false
}

// ApplyFailMode writes an empty HTTP 502 on close and reports true. Open writes nothing and reports false.
func ApplyFailMode(rw http.ResponseWriter, failMode string) bool {
	if configuration.EffectiveModsecFailMode(failMode) == configuration.ModsecFailModeClose {
		http.Error(rw, "", http.StatusBadGateway)
		return true
	}
	return false
}

// discardSidecarBody drains leftover sidecar bytes so the HTTP slot can be reused.
func (c *Client) discardSidecarBody(body io.Reader) {
	if _, errDrain := io.Copy(io.Discard, io.LimitReader(body, sidecarBodyDrainLimit)); errDrain != nil {
		c.log.Debug("modsecInspect:drainBody", "error", errDrain)
	}
}

// sidecarLogHost is the sidecar host for error logs. Query and userinfo stay off it.
func sidecarLogHost(modsecURL string) string {
	parsed, err := url.Parse(modsecURL)
	if err != nil || parsed.Host == "" {
		return "unknown"
	}
	return parsed.Host
}

// forwardResponse copies the sidecar block to the visitor: end-to-end headers except Server, then the body.
func forwardResponse(resp *http.Response, rw http.ResponseWriter) {
	dst := rw.Header()
	for name := range resp.Header {
		dst.Del(name)
	}
	wafhop.CopyEndToEndHeaders(dst, resp.Header, "Server")
	rw.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(rw, resp.Body)
}
