// Package crowdsec_bouncer_traefik_plugin implements a middleware that communicates with crowdsec.
package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"context"
	"net/http"
	"strings"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/appsec"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/bouncer"
	configuration "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// CreateConfig creates the default plugin configuration.
func CreateConfig() *configuration.Config {
	return configuration.New()
}

// New is the Traefik Yaegi constructor. It reclaims LAPI and AppSec backends and returns a per-router Bouncer.
// Stream/alone: one LAPI client per LAPI URL+key (CrowdSec one stream cursor per
// hashed key + outbound IP). Live/none: reclaim by LAPI identity. AppSec: reclaim by listener URL+key.
//
// New works on a snapshot of the config Traefik owns, and binds every reclaim Open to a context
// derived from the constructor ctx, so a constructor that fails partway releases what earlier steps
// already opened instead of leaving a LAPI stream ticker polling for the process lifetime.
//
// err is named so that defer can see which way New left; a bool would not survive a later return.
//
//nolint:nonamedreturns
func New(ctx context.Context, next http.Handler, config *configuration.Config, name string) (handler http.Handler, err error) {
	// Shallow copy: Config's []string and map[string]string fields still alias the caller's.
	// Nothing below mutates them in place, so whoever adds an in-place mutation must copy them too.
	prepared := *config
	prepared.LogLevel = strings.ToUpper(prepared.LogLevel)
	log := logger.NewWithFormat(prepared.LogLevel, prepared.LogFilePath, prepared.LogFormat)

	if err = configuration.ValidateParams(&prepared, log); err != nil {
		log.Error("New:validateParams " + err.Error())
		return nil, err
	}

	if err = lapi.Prepare(&prepared, log); err != nil {
		return nil, err
	}
	if err = appsec.Prepare(&prepared, log); err != nil {
		return nil, err
	}

	// bindCtx holds every incarnation this constructor opens. Releasing it on a failed New hands
	// them back; it stays a child of ctx, so canceling Traefik's context still releases them.
	bindCtx, releaseHolders := context.WithCancel(ctx)
	defer func() {
		if err != nil {
			releaseHolders()
		}
	}()

	var lapiClient *lapi.Client
	// Stream and alone poll GET /v1/decisions/stream. CrowdSec stores that
	// cursor on the bouncer row selected by hashed X-Api-Key plus the IP LAPI
	// sees (this process’s outbound address), not per middleware and not per
	// metrics interval. OpenStream keeps one ticker per URL+key in this process.
	if prepared.CrowdsecMode == configuration.StreamMode || prepared.CrowdsecMode == configuration.AloneMode {
		lapiClient, err = lapi.OpenStream(bindCtx, &prepared, log, name, pluginVersion)
		if err != nil {
			return nil, err
		}
	} else if prepared.CrowdsecMode != configuration.AppsecMode {
		// Live/none do not use stream_cursor. Two Clients on one key
		// stay valid (?ip= lookups). Reclaim by LAPI identity, including intervals.
		lapiClient, err = lapi.OpenLive(bindCtx, &prepared, log, name, pluginVersion)
		if err != nil {
			return nil, err
		}
	}

	var appsecClient *appsec.Client
	if prepared.CrowdsecAppsecEnabled {
		appsecClient, err = appsec.Open(bindCtx, &prepared, log, name, pluginVersion)
		if err != nil {
			return nil, err
		}
	}
	handler, err = bouncer.New(next, name, &prepared, lapiClient, appsecClient, log)
	return handler, err
}
