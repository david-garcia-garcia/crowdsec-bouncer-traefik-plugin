// Package crowdsec_bouncer_traefik_plugin implements a middleware that communicates with crowdsec.
package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/appsec"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/bouncer"
	configuration "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/instance"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// CreateConfig creates the default plugin configuration.
func CreateConfig() *configuration.Config {
	return configuration.New()
}

// New is the Traefik Yaegi constructor. It may Open named LAPI/AppSec clients, subscribe
// to names opened elsewhere, bounce this router, or hold clients and reject traffic.
func New(ctx context.Context, next http.Handler, config *configuration.Config, name string) (handler http.Handler, err error) {
	prepared := *config
	prepared.LogLevel = strings.ToUpper(prepared.LogLevel)
	log := logger.NewWithFormat(prepared.LogLevel, prepared.LogFilePath, prepared.LogFormat)

	if err = configuration.ValidateParams(&prepared, log); err != nil {
		log.Error("New:validateParams", "error", err)
		return nil, err
	}

	if err = lapi.Prepare(&prepared, log); err != nil {
		return nil, err
	}
	if err = appsec.Prepare(&prepared, log); err != nil {
		return nil, err
	}

	bindCtx, releaseHolders := context.WithCancel(ctx)
	defer func() {
		if err != nil {
			releaseHolders()
		}
	}()

	var lapiClient *lapi.Client
	lapiName := configuration.NamedLapiInstance(&prepared, name)
	if configuration.OpensLAPI(&prepared) {
		if prepared.LapiMode == configuration.StreamMode || prepared.LapiMode == configuration.AloneMode {
			lapiClient, err = lapi.OpenStream(bindCtx, &prepared, log, lapiName, pluginVersion)
		} else {
			lapiClient, err = lapi.OpenLive(bindCtx, &prepared, log, lapiName, pluginVersion)
		}
		if err != nil {
			return nil, err
		}
		if err = instance.PublishLAPI(lapiName, lapiClient); err != nil {
			return nil, err
		}
	}

	var appsecClient *appsec.Client
	appsecName := configuration.NamedAppsecInstance(&prepared, name)
	if configuration.OpensAppsec(&prepared) {
		appsecClient, err = appsec.Open(bindCtx, &prepared, log, appsecName, pluginVersion)
		if err != nil {
			return nil, err
		}
		if err = instance.PublishAppsec(appsecName, appsecClient); err != nil {
			return nil, err
		}
	}

	if prepared.BouncerHold {
		return newHoldHandler(log, name), nil
	}
	handler, err = bouncer.New(next, name, &prepared, lapiClient, appsecClient, log)
	return handler, err
}

// holdHandler rejects traffic on a placeholder router that only publishes clients.
type holdHandler struct {
	log  *slog.Logger
	name string
}

func newHoldHandler(log *slog.Logger, name string) http.Handler {
	return &holdHandler{log: log, name: name}
}

func (h *holdHandler) ServeHTTP(rw http.ResponseWriter, _ *http.Request) {
	h.log.Error("holder middleware received a request; this router publishes LAPI/AppSec clients and does not bounce", "name", h.name)
	http.Error(rw, "Service Unavailable", http.StatusServiceUnavailable)
}
