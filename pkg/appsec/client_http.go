package appsec

import (
	"log/slog"
	"net/http"
	"time"

	configuration "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

// transport is AppSec HTTP plus the API key.
// Stored on Client as atomic.Value: Yaegi v0.16 cannot take atomic.Pointer[T]
// from another package as a struct field.
type transport struct {
	httpClient                    *http.Client
	key                           string
	httpTimeoutSeconds            int64
	appsecTLSInsecureVerify       bool
	appsecTLSCertificateAuthority string
	appsecTLSCertificateBouncer   string
}

// newTransport builds HTTP+auth from cfg. AppSec TLS uses GetTLSConfigCrowdsec(..., true).
func newTransport(config *configuration.Config, log *slog.Logger) (*transport, error) {
	tlsConfig, err := configuration.GetTLSConfigCrowdsec(config, log, true)
	if err != nil {
		return nil, err
	}
	// Store effective seconds so AdoptTransport last-writes a shared-default change when the override is still 0.
	timeoutSeconds := config.EffectiveHTTPTimeoutSeconds(config.CrowdsecAppsecHTTPTimeoutSeconds)
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
		key:                           config.CrowdsecAppsecKey,
		httpTimeoutSeconds:            timeoutSeconds,
		appsecTLSInsecureVerify:       config.CrowdsecAppsecTLSInsecureVerify,
		appsecTLSCertificateAuthority: config.CrowdsecAppsecTLSCertificateAuthority,
		appsecTLSCertificateBouncer:   config.CrowdsecAppsecTLSCertificateBouncer,
	}, nil
}

// fieldsDiffer reports whether timeout or AppSec TLS extras changed.
func (t *transport) fieldsDiffer(other *transport) bool {
	if t == nil || other == nil {
		return t != other
	}
	return t.httpTimeoutSeconds != other.httpTimeoutSeconds ||
		t.appsecTLSInsecureVerify != other.appsecTLSInsecureVerify ||
		t.appsecTLSCertificateAuthority != other.appsecTLSCertificateAuthority ||
		t.appsecTLSCertificateBouncer != other.appsecTLSCertificateBouncer
}

type idleCloser interface {
	CloseIdleConnections()
}

func closeIdle(httpClient *http.Client) {
	if httpClient == nil {
		return
	}
	if closer, ok := httpClient.Transport.(idleCloser); ok {
		closer.CloseIdleConnections()
	}
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

// AdoptTransport replaces AppSec HTTP+auth with cfg and idle-closes the previous client.
// Last Store wins. Returns whether timeout or TLS extras changed.
func (c *Client) AdoptTransport(cfg *configuration.Config) (bool, error) {
	next, err := newTransport(cfg, c.log)
	if err != nil {
		return false, err
	}
	replaced := next.fieldsDiffer(c.currentTransport())
	previous, _ := c.transport.Swap(next).(*transport)
	if previous != nil {
		closeIdle(previous.httpClient)
	}
	if replaced && c.log != nil {
		c.log.Info("appsec transport replaced",
			"sessionKey", c.sessionKey,
			"httpTimeoutSeconds", next.httpTimeoutSeconds,
			"appsecTlsInsecureVerify", next.appsecTLSInsecureVerify,
			"appsecTlsCa", next.appsecTLSCertificateAuthority != "",
			"appsecTlsCert", next.appsecTLSCertificateBouncer != "",
		)
	}
	return replaced, nil
}
