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

// New is the Traefik Yaegi constructor. It opens owned LAPI/AppSec legs, publishes
// named slots, and returns a per-router Bouncer that late-binds via atomic.Value.
//
// New works on a snapshot of the config Traefik owns, and binds every reclaim Open to a
// child of the constructor ctx, so a constructor that fails partway releases what it opened.
func New(ctx context.Context, next http.Handler, config *configuration.Config, name string) (handler http.Handler, err error) {
	// Shallow copy: Config's []string and map[string]string fields still alias the caller's.
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
	configuration.PrepopulateInstanceNames(&prepared, name)

	bindCtx, releaseHolders := context.WithCancel(ctx)
	defer func() {
		if err != nil {
			releaseHolders()
		}
	}()

	if err = openAndPublishOwned(bindCtx, &prepared, log, name); err != nil {
		return nil, err
	}

	subscribeLAPI := prepared.Enabled && prepared.CrowdsecLapiInstanceName != ""
	subscribeAppSec := prepared.Enabled && prepared.CrowdsecAppsecInstanceName != ""
	handler, err = bouncer.New(next, name, &prepared, subscribeLAPI, subscribeAppSec, log)
	if err != nil {
		return nil, err
	}
	route, _ := handler.(*bouncer.Bouncer)
	if subscribeLAPI {
		instance.Subscribe(instance.LegLAPI, prepared.CrowdsecLapiInstanceName, instance.Subscriber{
			Value: route.LAPIBinding(), TraefikName: name, Log: log, HeaderScopes: prepared.DecisionScopeHeaders,
		})
	}
	if subscribeAppSec {
		instance.Subscribe(instance.LegAppSec, prepared.CrowdsecAppsecInstanceName, instance.Subscriber{
			Value: route.AppSecBinding(), TraefikName: name, Log: log,
		})
	}
	context.AfterFunc(ctx, func() {
		if subscribeLAPI {
			instance.Unsubscribe(instance.LegLAPI, prepared.CrowdsecLapiInstanceName, route.LAPIBinding())
		}
		if subscribeAppSec {
			instance.Unsubscribe(instance.LegAppSec, prepared.CrowdsecAppsecInstanceName, route.AppSecBinding())
		}
	})
	return handler, err
}

func openAndPublishOwned(bindCtx context.Context, prepared *configuration.Config, log *slog.Logger, name string) error {
	var lapiClient *lapi.Client
	var err error
	if prepared.CrowdsecLapiEnabled {
		if prepared.CrowdsecMode == configuration.StreamMode || prepared.CrowdsecMode == configuration.AloneMode {
			lapiClient, err = lapi.OpenStream(bindCtx, prepared, log, name, pluginVersion)
		} else {
			lapiClient, err = lapi.OpenLive(bindCtx, prepared, log, name, pluginVersion)
		}
		if err != nil {
			return err
		}
		unpublishRenamedLAPI(lapiClient, prepared.CrowdsecLapiInstanceName, name)
	}

	var appsecClient *appsec.Client
	if prepared.CrowdsecAppsecEnabled {
		appsecClient, err = appsec.Open(bindCtx, prepared, log, name, pluginVersion)
		if err != nil {
			return err
		}
		unpublishRenamedAppSec(appsecClient, prepared.CrowdsecAppsecInstanceName, name)
	}

	attempts := make([]instance.PublishAttempt, 0, 2)
	if lapiClient != nil {
		attempts = append(attempts, instance.PublishAttempt{
			Leg: instance.LegLAPI, InstanceName: prepared.CrowdsecLapiInstanceName,
			Publisher: name, Client: lapiClient, Log: log,
		})
	}
	if appsecClient != nil {
		attempts = append(attempts, instance.PublishAttempt{
			Leg: instance.LegAppSec, InstanceName: prepared.CrowdsecAppsecInstanceName,
			Publisher: name, Client: appsecClient, Log: log,
		})
	}
	if err = instance.PublishAll(attempts); err != nil {
		return err
	}
	if lapiClient != nil {
		lapiClient.SetPublishedName(prepared.CrowdsecLapiInstanceName)
	}
	if appsecClient != nil {
		appsecClient.SetPublishedName(prepared.CrowdsecAppsecInstanceName)
	}
	return nil
}

func unpublishRenamedLAPI(client *lapi.Client, instanceName, publisher string) {
	stored := client.LastPublishedName()
	if stored == "" || stored == instanceName {
		return
	}
	instance.Unpublish(instance.LegLAPI, stored, client, publisher)
}

func unpublishRenamedAppSec(client *appsec.Client, instanceName, publisher string) {
	stored := client.LastPublishedName()
	if stored == "" || stored == instanceName {
		return
	}
	instance.Unpublish(instance.LegAppSec, stored, client, publisher)
}
