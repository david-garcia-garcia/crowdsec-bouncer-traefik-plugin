package lapi

import (
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

// NewTestLapiFailureActionClient returns a client that only exposes LapiFailureAction.
func NewTestLapiFailureActionClient(action string) *Client {
	return &Client{
		lapiFailureAction: configuration.EffectiveFailureAction(action),
	}
}
