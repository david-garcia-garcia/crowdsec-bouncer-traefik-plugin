package crowdsecconnection

import (
	"log/slog"
	"net/http"
	"net/url"
)

// NewTestAppsecConnection returns a CrowdsecConnection that only performs AppsecQuery against client.
func NewTestAppsecConnection(appsecURL *url.URL, client *http.Client, log *slog.Logger) *CrowdsecConnection {
	return &CrowdsecConnection{
		appsecScheme:     appsecURL.Scheme,
		appsecHost:       appsecURL.Host,
		appsecPath:       "/",
		httpAppsecClient: client,
		log:              log,
	}
}
