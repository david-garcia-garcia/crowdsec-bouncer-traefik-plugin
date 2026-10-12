package modsecurity

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

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
	if skipHop, wrote := c.denyAdmission(rw, req, failMode); skipHop {
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
		return c.handleSidecarDoError(rw, req, failMode, err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			c.log.Error("fail to close WAF response body", "error", closeErr)
		}
	}()

	if resp.StatusCode >= 300 && resp.StatusCode < 500 {
		c.reportOutcome(true)
		if remediationHeader != "" {
			rw.Header().Set(remediationHeader, "ban:"+headerReasonModsec)
		}
		forwardResponse(resp, rw)
		discardSidecarBody(resp.Body)
		return true
	}
	discardSidecarBody(resp.Body)
	if resp.StatusCode >= 500 {
		c.reportOutcome(false)
		c.log.Error("fail to send HTTP request to modsec", "error", fmt.Errorf("waf status %d", resp.StatusCode), "inbound", req.Context().Err())
		return c.serveFailClosed(rw, failMode)
	}
	c.reportOutcome(true)
	return false
}

// rejectDeniedVerbBody writes HTTP 400 when a listed method carries a readable body byte.
func (c *Client) rejectDeniedVerbBody(rw http.ResponseWriter, req *http.Request) bool {
	if !c.denyVerbsWithBody[req.Method] {
		return false
	}
	limitedBody := http.MaxBytesReader(rw, req.Body, 1)
	testByte := make([]byte, 1)
	if n, err := limitedBody.Read(testByte); n > 0 || err == nil {
		c.log.Warn("HTTP request should not have a body, rejecting", "method", req.Method)
		http.Error(rw, "HTTP "+req.Method+" requests should not have a body", http.StatusBadRequest)
		return true
	}
	return false
}

// denyAdmission consults the Gate after deny-verbs and body-limit.
// skipHop means Inspect must not call the sidecar. wrote is Inspect's return value.
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

func (c *Client) serveFailClosed(rw http.ResponseWriter, failMode string) bool {
	if configuration.EffectiveModsecFailMode(failMode) == configuration.ModsecFailModeClose {
		http.Error(rw, "", http.StatusBadGateway)
		return true
	}
	return false
}

func (c *Client) reportOutcome(success bool) {
	if c.gate == nil {
		return
	}
	if err := c.gate.Report(gateKey, success); err != nil {
		c.log.Error("fail to report WAF admission outcome", "error", err, "success", success)
	}
}

func discardSidecarBody(body io.Reader) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, sidecarBodyDrainLimit))
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
