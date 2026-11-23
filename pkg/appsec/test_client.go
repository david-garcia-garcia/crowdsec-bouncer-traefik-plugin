package appsec

import (
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

// NewTestClient returns a Client that only performs Query against client.
func NewTestClient(appsecURL *url.URL, client *http.Client, log *slog.Logger) *Client {
	appsecClient := &Client{
		appsecScheme:    appsecURL.Scheme,
		appsecHost:      appsecURL.Host,
		appsecPath:      "/",
		appsecBodyLimit: configuration.DefaultAppsecBodyLimit,
		bodyReadTimeout: time.Duration(configuration.DefaultBodyReadTimeoutSeconds) * time.Second,
		log:             log,
	}
	appsecClient.transport.Store(&transport{httpClient: client})
	return appsecClient
}
