package appsec

import (
	"log/slog"
	"net/http"
	"net/url"
)

// NewTestClient returns a Client that only performs Query against client.
func NewTestClient(appsecURL *url.URL, client *http.Client, log *slog.Logger) *Client {
	appsecClient := &Client{
		appsecScheme:    appsecURL.Scheme,
		appsecHost:      appsecURL.Host,
		appsecPath:      "/",
		appsecBodyLimit: 10485760,
		log:             log,
	}
	appsecClient.transport.Store(&transport{httpClient: client})
	return appsecClient
}
