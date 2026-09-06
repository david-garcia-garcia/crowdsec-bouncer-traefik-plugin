package lapi

import (
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

// NewTestLapiFailureActionConnection returns a connection that only exposes LapiFailureAction.
func NewTestLapiFailureActionConnection(action string) *Connection {
	return &Connection{
		lapiFailureAction: configuration.EffectiveFailureAction(action),
	}
}
