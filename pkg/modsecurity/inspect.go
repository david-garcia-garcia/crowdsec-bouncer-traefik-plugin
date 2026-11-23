package modsecurity

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/wafhop"
)

// sidecarBodyDrainLimit caps how much of an unused sidecar body is drained, so keep-alive can reuse the slot.
const sidecarBodyDrainLimit = 256 << 10

// MsgUnavailable is the debounced ERROR line when the sidecar gives no verdict.
const MsgUnavailable = "crowdsec modsec sidecar unavailable"

var (
	// ErrUnavailable means the sidecar gave no verdict: unreachable, timeout, HTTP 5xx, or a request that
	// could not be built. The bouncer applies bouncerModsecFailureAction.
	ErrUnavailable = errors.New("modsecInspect:unavailable")
	// ErrGateSkip means the admission gate is backing off and the sidecar was not called.
	// As for AppSec, the bouncer answers it with bouncerModsecBackOffAction, not the failure action.
	ErrGateSkip = errors.New("modsecInspect:unhealthySkip")
	// ErrBodyTooLarge means the body is over modsecBodyLimit. The bouncer answers 413.
	ErrBodyTooLarge = wafhop.ErrBodyTooLarge
)

// Inspect copies req to the CRS sidecar and classifies its status. It never writes the client response.
//
//   - nil, nil: allow (sidecar 2xx). The caller continues to next.
//   - resp, nil: block (sidecar 3xx or 4xx). The caller sends it with WriteBlock, which closes it.
//   - nil, err: ErrUnavailable, ErrGateSkip, ErrBodyTooLarge, wafhop.ErrBodyReadTimeout,
//     wafhop.ErrClientDisconnected, or wafhop.ErrClientBodyRead.
//
// Any body is read before admission, with or without Content-Length. ctrl is the inbound request's
// response controller: a body without Content-Length is read under modsecBodyReadTimeoutSeconds, and
// ctrl cuts that read when the deadline fires (nil falls back to closing the body, which cuts HTTP/2 only).
func (c *Client) Inspect(req *http.Request, ctrl *http.ResponseController) (*http.Response, error) {
	var body []byte
	if wafhop.HasBody(req) {
		read, err := wafhop.ReadBody(req, c.bodyLimit, wafhop.RejectOverLimit, ctrl, c.bodyReadTimeout)
		if err != nil {
			return nil, err
		}
		body = read
	}

	ticket, admitErr := c.gate.Admit(req.Context())
	if admitErr != nil {
		if wafhop.IsInboundCanceled(req, admitErr) {
			return nil, wafhop.ErrClientDisconnected
		}
		c.log.Error("fail to admit ModSec request", "error", admitErr)
		return nil, fmt.Errorf("%w: admission: %s", ErrUnavailable, admitErr.Error())
	}
	if !ticket.Admitted {
		return nil, ErrGateSkip
	}

	proxyReq, err := http.NewRequestWithContext(req.Context(), req.Method, c.modsecURL+req.URL.RequestURI(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %s", ErrUnavailable, err.Error())
	}
	// The sidecar sees the end-to-end request. Hop-by-hop headers belong to the client connection,
	// and Content-Length is rebuilt from the bytes forwarded.
	wafhop.CopyEndToEndHeaders(proxyReq.Header, req.Header, "Content-Length")
	proxyReq.Host = req.Host

	resp, err := c.httpClient.Do(proxyReq)
	if err != nil {
		if wafhop.IsInboundCanceled(req, err) {
			return nil, wafhop.ErrClientDisconnected
		}
		c.gate.Record(ticket, false)
		logger.Debounced(c.log, slog.LevelError, 5*time.Second, MsgUnavailable, "host", sidecarLogHost(c.modsecURL), "reason", "unreachable", "error", transportCause(err))
		return nil, fmt.Errorf("%w: %s", ErrUnavailable, err.Error())
	}

	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 500:
		c.gate.Record(ticket, true)
		return resp, nil
	case resp.StatusCode >= 500:
		c.closeSidecarBody(resp.Body)
		c.gate.Record(ticket, false)
		logger.Debounced(c.log, slog.LevelError, 5*time.Second, MsgUnavailable, "host", sidecarLogHost(c.modsecURL), "reason", "status", "statusCode", resp.StatusCode)
		return nil, fmt.Errorf("%w: sidecar status %d", ErrUnavailable, resp.StatusCode)
	default:
		c.closeSidecarBody(resp.Body)
		c.gate.Record(ticket, true)
		return nil, nil //nolint:nilnil // a nil response with a nil error is the allow verdict
	}
}

// WriteBlock copies a sidecar block to the visitor and closes it: end-to-end headers except Server,
// the status, then the page ModSecurity produced. A header already on rw keeps its value unless the
// sidecar sends the same name.
func WriteBlock(rw http.ResponseWriter, resp *http.Response) {
	defer func() { _ = resp.Body.Close() }()
	dst := rw.Header()
	for name := range resp.Header {
		dst.Del(name)
	}
	wafhop.CopyEndToEndHeaders(dst, resp.Header, "Server")
	rw.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(rw, resp.Body)
}

// closeSidecarBody drains leftover sidecar bytes and closes the body so the HTTP slot can be reused.
func (c *Client) closeSidecarBody(body io.ReadCloser) {
	if _, errDrain := io.Copy(io.Discard, io.LimitReader(body, sidecarBodyDrainLimit)); errDrain != nil {
		c.log.Debug("modsecInspect:drainBody", "error", errDrain)
	}
	if errClose := body.Close(); errClose != nil {
		c.log.Debug("modsecInspect:closeBody", "error", errClose)
	}
}

// transportCause is the transport error without the request URL. The URL carries the visitor's path
// and query, which stay off logs like in sidecarLogHost.
func transportCause(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		return urlErr.Err
	}
	return err
}

// sidecarLogHost is the sidecar host for error logs. Query and userinfo stay off it.
func sidecarLogHost(modsecURL string) string {
	parsed, err := url.Parse(modsecURL)
	if err != nil || parsed.Host == "" {
		return "unknown"
	}
	return parsed.Host
}
