package crowdsecconnection

import (
	"log/slog"
	"net/http"
	"net/url"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

// NewTestAppsecConnection returns a CrowdsecConnection that only performs AppsecQuery against client.
func NewTestAppsecConnection(appsecURL *url.URL, client *http.Client, log *slog.Logger) *CrowdsecConnection {
	return &CrowdsecConnection{
		appsecScheme:     appsecURL.Scheme,
		appsecHost:       appsecURL.Host,
		appsecPath:       "/",
		appsecBodyLimit:  10485760,
		httpAppsecClient: client,
		log:              log,
	}
}

// NewTestLapiFailureActionConnection returns a connection that only exposes LapiFailureAction.
func NewTestLapiFailureActionConnection(action string) *CrowdsecConnection {
	return &CrowdsecConnection{
		lapiFailureAction: configuration.EffectiveFailureAction(action),
	}
}
