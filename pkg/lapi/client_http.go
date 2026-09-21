package lapi

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	configuration "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

const (
	crowdsecLapiHeader      = "X-Api-Key"
	crowdsecLapiRoute       = "v1/decisions"
	crowdsecLapiStreamRoute = "v1/decisions/stream"
	crowdsecCapiHost        = "api.crowdsec.net"
	crowdsecCapiHeader      = "Authorization"
	crowdsecCapiLoginRoute  = "v2/watchers/login"
	crowdsecCapiStreamRoute = "v2/decisions/stream"
)

// Login is the body returned from Crowdsec Login CAPI.
type Login struct {
	Code   int    `json:"code"`
	Token  string `json:"token"`
	Expire string `json:"expire"`
}

// loginRequest is the CAPI watchers-login body getToken posts from stored Client credentials.
//
//nolint:tagliatelle // CAPI LoginRequest names are machine_id, password, scenarios.
type loginRequest struct {
	MachineID string   `json:"machine_id"`
	Password  string   `json:"password"`
	Scenarios []string `json:"scenarios"`
}

// transport is LAPI HTTP plus the request header name and CAPI/LAPI key.
// Stored on Client as atomic.Value: Yaegi v0.16 cannot take atomic.Pointer[T]
// from another package as a struct field.
type transport struct {
	httpClient                  *http.Client
	header                      string
	key                         string
	httpTimeoutSeconds          int64
	lapiTLSInsecureVerify       bool
	lapiTLSCertificateAuthority string
	lapiTLSCertificateBouncer   string
}

// newTransport builds HTTP+auth from cfg. Alone uses the CAPI header and no LAPI TLS.
func newTransport(config *configuration.Config, log *slog.Logger) (*transport, error) {
	header := crowdsecLapiHeader
	var tlsConfig *tls.Config
	if config.LapiMode == configuration.AloneMode {
		header = crowdsecCapiHeader
	} else {
		var err error
		tlsConfig, err = configuration.GetTLSConfigCrowdsec(config, log, false)
		if err != nil {
			return nil, err
		}
	}
	// Store effective seconds so AdoptTransport last-writes a shared-default change when the override is still 0.
	timeoutSeconds := config.EffectiveHTTPTimeoutSeconds(config.LapiHTTPTimeoutSeconds)
	return &transport{
		httpClient: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     30 * time.Second,
				TLSClientConfig:     tlsConfig,
			},
			Timeout: time.Duration(timeoutSeconds) * time.Second,
		},
		header:                      header,
		key:                         config.LapiKey,
		httpTimeoutSeconds:          timeoutSeconds,
		lapiTLSInsecureVerify:       config.LapiTLSInsecureVerify,
		lapiTLSCertificateAuthority: config.LapiTLSCa,
		lapiTLSCertificateBouncer:   config.LapiTLSCert,
	}, nil
}

// clientCertCount is how many client certificates the HTTP TLS config holds.
func (t *transport) clientCertCount() int {
	if t == nil || t.httpClient == nil {
		return 0
	}
	httpTransport, ok := t.httpClient.Transport.(*http.Transport)
	if !ok || httpTransport.TLSClientConfig == nil {
		return 0
	}
	return len(httpTransport.TLSClientConfig.Certificates)
}

// fieldsDiffer reports whether timeout or LAPI TLS extras changed.
func (t *transport) fieldsDiffer(other *transport) bool {
	if t == nil || other == nil {
		return t != other
	}
	return t.httpTimeoutSeconds != other.httpTimeoutSeconds ||
		t.lapiTLSInsecureVerify != other.lapiTLSInsecureVerify ||
		t.lapiTLSCertificateAuthority != other.lapiTLSCertificateAuthority ||
		t.lapiTLSCertificateBouncer != other.lapiTLSCertificateBouncer
}

func closeIdle(httpClient *http.Client) {
	if httpClient == nil {
		return
	}
	if t, ok := httpClient.Transport.(*http.Transport); ok {
		t.CloseIdleConnections()
	}
}

func isReverseProxyError(statusCode int) bool {
	return statusCode == http.StatusBadGateway ||
		statusCode == http.StatusServiceUnavailable ||
		statusCode == http.StatusGatewayTimeout
}

// currentTransport is the stored HTTP+auth snapshot, or nil before the first Store.
func (c *Client) currentTransport() *transport {
	stored := c.transport.Load()
	if stored == nil {
		return nil
	}
	loaded, _ := stored.(*transport)
	return loaded
}

// AdoptTransport replaces LAPI HTTP+auth with cfg and idle-closes the previous client.
// Last Store wins. Returns whether timeout or TLS extras changed.
func (c *Client) AdoptTransport(cfg *configuration.Config) (bool, error) {
	next, err := newTransport(cfg, c.log)
	if err != nil {
		return false, err
	}
	// Preserve a CAPI token already written on the live transport when the
	// new cfg still has an empty LAPI key (alone mode after getToken).
	if previous := c.currentTransport(); previous != nil && next.key == "" && previous.key != "" {
		next.key = previous.key
	}
	replaced := next.fieldsDiffer(c.currentTransport())
	previous, _ := c.transport.Swap(next).(*transport)
	if previous != nil {
		closeIdle(previous.httpClient)
	}
	if replaced && c.log != nil {
		c.log.Info("lapi transport replaced",
			"sessionKey", c.sessionKey,
			"httpTimeoutSeconds", next.httpTimeoutSeconds,
			"lapiTlsInsecureVerify", next.lapiTLSInsecureVerify,
			"lapiTlsCa", next.lapiTLSCertificateAuthority != "",
			"lapiTlsCert", next.lapiTLSCertificateBouncer != "",
		)
	}
	return replaced, nil
}

// getToken POSTs CAPI watchers-login and writes the token on the stored transport.
func (c *Client) getToken() error {
	loginURL := url.URL{
		Scheme: c.crowdsecScheme,
		Host:   c.crowdsecHost,
		Path:   crowdsecCapiLoginRoute,
	}
	// Encode stored credentials; interpolation cannot keep quotes and backslashes valid JSON.
	loginData, err := json.Marshal(loginRequest{
		MachineID: c.crowdsecMachineID,
		Password:  c.crowdsecPassword,
		Scenarios: c.crowdsecScenarios,
	})
	if err != nil {
		return fmt.Errorf("getToken:marshal %w", err)
	}
	// The login request must never renew a token: a 401 here would recurse into getToken forever.
	body, err := c.sendQuery(loginURL.String(), loginData, false)
	if err != nil {
		return err
	}
	var login Login
	err = json.Unmarshal(body, &login)
	if err != nil {
		return fmt.Errorf("getToken:parsingBody %w", err)
	}
	// After sendQuery 2xx, store a non-empty token. Do not require JSON code==200:
	// official WatcherAuthResponse marks code omitempty.
	if len(login.Token) > 0 {
		// Write the token on the stored transport, not a write-once Client field.
		current := c.currentTransport()
		if current == nil {
			return errors.New("getToken: missing transport")
		}
		updated := *current
		updated.key = login.Token
		c.transport.Store(&updated)
		return nil
	}
	c.log.Warn("getToken", "statusCode", login.Code)
	return errors.New("getToken statusCode:" + strconv.Itoa(login.Code))
}

// drainResponse consumes leftover bytes so the LAPI HTTP connection can be reused.
func (c *Client) drainResponse(res *http.Response) {
	if _, errDrain := io.Copy(io.Discard, res.Body); errDrain != nil {
		c.log.Debug("crowdsecQuery:drainBody", "error", errDrain)
	}
	if errClose := res.Body.Close(); errClose != nil {
		c.log.Error("crowdsecQuery:closeBody", "error", errClose)
	}
}

// crowdsecQuery sends one LAPI/CAPI request, renewing the alone-mode CAPI token once on a 401.
func (c *Client) crowdsecQuery(stringURL string, data []byte) ([]byte, error) {
	return c.sendQuery(stringURL, data, true)
}

// sendQuery sends one LAPI/CAPI request. On an alone-mode 401 with mayRenewToken set, it renews the
// CAPI token and replays the same method and the same body once, with that permission cleared, so a
// second 401 returns the status error instead of recursing.
func (c *Client) sendQuery(stringURL string, data []byte, mayRenewToken bool) ([]byte, error) {
	current := c.currentTransport()
	if current == nil || current.httpClient == nil {
		return nil, errors.New("crowdsecQuery: missing transport")
	}
	var req *http.Request
	if len(data) > 0 {
		req, _ = http.NewRequest(http.MethodPost, stringURL, bytes.NewBuffer(data))
	} else {
		req, _ = http.NewRequest(http.MethodGet, stringURL, nil)
	}
	req.Header.Set(current.header, current.key)
	req.Header.Set("User-Agent", "Crowdsec-Bouncer-Traefik-Plugin/"+c.pluginVersion)

	res, err := current.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crowdsecQuery:unreachable url:%s %w", stringURL, err)
	}
	// Drain every live response, including 502/503/504, so keep-alive can reuse the slot.
	defer c.drainResponse(res)
	if isReverseProxyError(res.StatusCode) {
		return nil, fmt.Errorf("crowdsecQuery:unreachable url:%s statusCode:%d", stringURL, res.StatusCode)
	}
	if res.StatusCode == http.StatusUnauthorized && c.lapiMode == configuration.AloneMode && mayRenewToken {
		if errToken := c.getToken(); errToken != nil {
			return nil, fmt.Errorf("crowdsecQuery:renewToken url:%s %w", stringURL, errToken)
		}
		return c.sendQuery(stringURL, data, false)
	}

	statusStr := strconv.Itoa(res.StatusCode)
	if len(statusStr) < 1 || statusStr[0] != '2' {
		return nil, fmt.Errorf("crowdsecQuery method:%s url:%s, statusCode:%d (expected: 2xx)", req.Method, stringURL, res.StatusCode)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("crowdsecQuery:readBody %w", err)
	}
	return body, nil
}
