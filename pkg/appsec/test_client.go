package appsec

import (
	"log/slog"
	"net/http"
	"net/url"
)

// NewTestClient returns a Client that only performs Query against client.
func NewTestClient(appsecURL *url.URL, client *http.Client, log *slog.Logger) *Client {
	return NewTestClientWithBodyLimit(appsecURL, client, log, 10485760)
}

// NewTestClientWithBodyLimit returns a test Client with a custom AppSec body limit.
func NewTestClientWithBodyLimit(appsecURL *url.URL, client *http.Client, log *slog.Logger, bodyLimit int64) *Client {
	return &Client{
		appsecScheme:    appsecURL.Scheme,
		appsecHost:      appsecURL.Host,
		appsecPath:      "/",
		appsecBodyLimit: bodyLimit,
		httpClient:      client,
		log:             log,
	}
}
