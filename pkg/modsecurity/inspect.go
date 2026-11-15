package modsecurity

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/admission"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

const sidecarBodyDrainLimit = 256 << 10

const headerReasonModsec = "modsec"

// Inspect copies req to the CRS sidecar and classifies the status.
// failMode is per-router open|close. remediationHeader is the optional ban:modsec name.
// True means the response was written. False means the caller continues to next.
func (c *Client) Inspect(rw http.ResponseWriter, req *http.Request, failMode, remediationHeader string) bool {
	if c.rejectDeniedVerbBody(rw, req) {
		return true
	}
	body, err := c.readInboundBody(rw, req)
	if err != nil {
		c.replyInboundBodyReadFailure(rw, req, err)
		return true
	}
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	ticket, skipHop, wrote := c.admitSidecarHop(rw, req, failMode)
	if skipHop {
		return wrote
	}

	proxyReq, err := http.NewRequestWithContext(req.Context(), req.Method, c.modsecURL+req.URL.RequestURI(), bodyReader)
	if err != nil {
		c.log.Error("fail to prepare forwarded request", "error", err)
		http.Error(rw, "", http.StatusBadGateway)
		return true
	}
	proxyReq.Header = make(http.Header, len(req.Header))
	for name, val := range req.Header {
		proxyReq.Header[name] = val
	}
	proxyReq.Host = req.Host

	resp, err := c.httpClient.Do(proxyReq)
	if err != nil {
		return c.replySidecarDoError(rw, req, failMode, ticket, err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			c.log.Error("fail to close WAF response body", "error", closeErr)
		}
	}()

	if resp.StatusCode >= 300 && resp.StatusCode < 500 {
		c.reportOutcome(ticket, true)
		if remediationHeader != "" {
			rw.Header().Set(remediationHeader, "ban:"+headerReasonModsec)
		}
		forwardResponse(resp, rw)
		c.discardSidecarBody(resp.Body)
		return true
	}
	c.discardSidecarBody(resp.Body)
	if resp.StatusCode >= 500 {
		c.reportOutcome(ticket, false)
		c.log.Error("fail to send HTTP request to modsec", "error", fmt.Errorf("waf status %d", resp.StatusCode), "inbound", req.Context().Err())
		return c.applyFailMode(rw, failMode)
	}
	c.reportOutcome(ticket, true)
	return false
}

// rejectDeniedVerbBody writes HTTP 400 when a listed method carries a readable body byte.
func (c *Client) rejectDeniedVerbBody(rw http.ResponseWriter, req *http.Request) bool {
	if !c.denyVerbsWithBody[req.Method] {
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

// admitSidecarHop consults the Gate after deny-verbs and body-limit.
// skipHop means Inspect must not call the sidecar. wrote is Inspect's return value.
// The gate logs once when backoff starts and once when it ends, never per skipped request.
func (c *Client) admitSidecarHop(rw http.ResponseWriter, req *http.Request, failMode string) (ticket admission.Ticket, skipHop bool, wrote bool) {
	ticket, allowErr := c.gate.Admit(req.Context())
	if allowErr != nil {
		if errors.Is(allowErr, context.Canceled) || errors.Is(req.Context().Err(), context.Canceled) {
			c.log.Info("inbound request canceled; WAF call aborted", "error", allowErr, "inbound", req.Context().Err())
			http.Error(rw, "", http.StatusBadGateway)
			return ticket, true, true
		}
		c.log.Error("fail to admit WAF request", "error", allowErr)
		return ticket, true, c.applyFailMode(rw, failMode)
	}
	if !ticket.Admitted {
		return ticket, true, c.applyFailMode(rw, failMode)
	}
	return ticket, false, false
}

// replySidecarDoError classifies inbound cancel vs sidecar miss after Client.Do fails.
func (c *Client) replySidecarDoError(rw http.ResponseWriter, req *http.Request, failMode string, ticket admission.Ticket, err error) bool {
	inboundErr := req.Context().Err()
	if errors.Is(err, context.Canceled) || errors.Is(inboundErr, context.Canceled) {
		c.log.Info("inbound request canceled; WAF call aborted", "error", err, "inbound", inboundErr)
		http.Error(rw, "", http.StatusBadGateway)
		return true
	}
	c.reportOutcome(ticket, false)
	c.log.Error("fail to send HTTP request to modsec", "host", sidecarLogHost(c.modsecURL), "inbound", inboundErr)
	return c.applyFailMode(rw, failMode)
}

func (c *Client) replyInboundBodyReadFailure(rw http.ResponseWriter, _ *http.Request, err error) {
	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		c.log.Warn("request body too large", "limit", maxBytesErr.Limit, "maxBodySizeBytes", c.bodyLimit)
		http.Error(rw, "Request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	c.log.Error("fail to read incoming request", "error", err)
	http.Error(rw, "", http.StatusBadGateway)
}

// applyFailMode writes empty 502 on close and continues on open.
func (c *Client) applyFailMode(rw http.ResponseWriter, failMode string) bool {
	if configuration.EffectiveModsecFailMode(failMode) == configuration.ModsecFailModeClose {
		http.Error(rw, "", http.StatusBadGateway)
		return true
	}
	return false
}

func (c *Client) reportOutcome(ticket admission.Ticket, success bool) {
	if err := c.gate.Report(ticket, success); err != nil {
		c.log.Error("fail to report WAF admission outcome", "error", err, "success", success)
	}
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

func headerValuesContainToken(values []string, token string) bool {
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

func forwardResponse(resp *http.Response, rw http.ResponseWriter) {
	dst := rw.Header()
	connectionValues := resp.Header.Values("Connection")
	for k, vv := range resp.Header {
		if omitSidecarResponseHeader(k, connectionValues) {
			continue
		}
		dst[k] = append(dst[k][:0], vv...)
	}
	rw.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(rw, resp.Body)
}

func omitSidecarResponseHeader(name string, connectionValues []string) bool {
	if strings.EqualFold(name, "Server") {
		return true
	}
	switch http.CanonicalHeaderKey(name) {
	case "Connection", "Keep-Alive", "Transfer-Encoding", "Upgrade", "Te", "Trailer":
		return true
	}
	if strings.HasPrefix(strings.ToLower(name), "proxy-") {
		return true
	}
	return headerValuesContainToken(connectionValues, name)
}
