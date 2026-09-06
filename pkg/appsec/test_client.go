package appsec

import (
	"log/slog"
	"net/http"
	"net/url"
)

// NewTestClient returns a Client that only performs Query against client.
func NewTestClient(appsecURL *url.URL, client *http.Client, log *slog.Logger) *Client {
	return &Client{
		appsecScheme:   appsecURL.Scheme,
		appsecHost:     appsecURL.Host,
		appsecPath:     "/",
		appsecBodyLimit: 10485760,
		httpClient:     client,
		log:            log,
	}
}
