// Package crowdsec_bouncer_traefik_plugin is the Traefik Yaegi entry (CreateConfig / New).
//
// Each New is one middleware. Per leg (LAPI, AppSec, captcha, ModSec, rate limit) it may own a Client,
// bounce against a named instance, both, or neither.
//
//	Open:          reclaim holder. Keeps that Client alive (stream ticker, HTTP).
//	               Last holder gone → Sleep, then Close after table grace.
//	ClearPublisher: this Traefik name no longer owns the leg; drop its aliases
//	               so watchers unbind. Do not Clear a still-owned reconstruct
//	               or subscribers flash empty before SetAlias.
//	SetAlias:      publish the instance name to the Client just Opened.
//	               Exclusive: a second publisher fails New.
//	Watch:         subscriber. Copies the current Client (or typed nil) into
//	               the Bouncer's atomic.Value. Not a holder — does not keep
//	               the Client alive and does not Close it.
//	valueChanged:  Watch's func(any). The any is reclaim.Published, whose Value
//	               is the client, or the typed empty when the alias is clear.
//	               The bouncer stores that into its own binding and validates it.
//	               Watch drops the subscriber when its ctx is done. The backend
//	               stays up if another holder still Opened it.
package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/appsec"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/bouncer"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/captcha"
	configuration "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/modsecurity"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ratelimit"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

const (
	legLAPI      = "lapi"
	legAppSec    = "appsec"
	legCaptcha   = "captcha"
	legModsec    = "modsec"
	legRateLimit = "ratelimit"
)

// publishedLeg is one leg New may own (Open + SetAlias) and subscribe to (Watch) under an instance name.
// Plain values and funcs, no generics: Yaegi v0.16 cannot run a generic type named through a package qualifier.
type publishedLeg struct {
	group        string // reclaim group, alias prefix, and log "leg" attr
	enabled      func(config *configuration.Config) bool
	instanceName func(config *configuration.Config) string
	// prepare resolves secrets and fills an omitted instance name with the Traefik name when owned.
	prepare      func(config *configuration.Config, log *slog.Logger, traefikName string) error
	open         func(bindCtx context.Context, config *configuration.Config, log *slog.Logger, traefikName string) error
	ownershipKey func(config *configuration.Config, traefikName string) string
	subscribe    func(subscriptions *bouncer.Subscriptions) // marks this leg on the route's subscriptions
	empty        any                                        // typed nil Watch stores while the alias is clear
	receive      func(route *bouncer.Bouncer) func(any)     // the route's Watch callback for this leg
}

// publishedLegs is every published leg in open and claim order. A failed claim clears the
// enabled legs before it, so the order is also the rollback order.
func publishedLegs() []publishedLeg {
	return []publishedLeg{
		{
			group:        legLAPI,
			enabled:      func(config *configuration.Config) bool { return config.LapiEnabled },
			instanceName: func(config *configuration.Config) string { return config.LapiInstanceName },
			prepare:      lapi.Prepare,
			open: func(bindCtx context.Context, config *configuration.Config, log *slog.Logger, traefikName string) error {
				_, err := lapi.Open(bindCtx, config, log, traefikName, pluginVersion)
				return err
			},
			ownershipKey: lapi.OwnershipKey,
			subscribe:    func(subscriptions *bouncer.Subscriptions) { subscriptions.LAPI = true },
			empty:        (*lapi.Client)(nil),
			receive:      func(route *bouncer.Bouncer) func(any) { return route.ReceiveLAPI },
		},
		{
			group:        legAppSec,
			enabled:      func(config *configuration.Config) bool { return config.AppsecEnabled },
			instanceName: func(config *configuration.Config) string { return config.AppsecInstanceName },
			prepare:      appsec.Prepare,
			open: func(bindCtx context.Context, config *configuration.Config, log *slog.Logger, traefikName string) error {
				_, err := appsec.Open(bindCtx, config, log, traefikName, pluginVersion)
				return err
			},
			ownershipKey: appsec.Key,
			subscribe:    func(subscriptions *bouncer.Subscriptions) { subscriptions.AppSec = true },
			empty:        (*appsec.Client)(nil),
			receive:      func(route *bouncer.Bouncer) func(any) { return route.ReceiveAppSec },
		},
		{
			group:        legCaptcha,
			enabled:      func(config *configuration.Config) bool { return config.CaptchaEnabled },
			instanceName: func(config *configuration.Config) string { return config.CaptchaInstanceName },
			prepare:      captcha.Prepare,
			open: func(bindCtx context.Context, config *configuration.Config, log *slog.Logger, traefikName string) error {
				_, err := captcha.Open(bindCtx, config, log, traefikName, pluginVersion)
				return err
			},
			ownershipKey: captcha.OwnershipKey,
			subscribe:    func(subscriptions *bouncer.Subscriptions) { subscriptions.Captcha = true },
			empty:        (*captcha.Client)(nil),
			receive:      func(route *bouncer.Bouncer) func(any) { return route.ReceiveCaptcha },
		},
		{
			group:        legModsec,
			enabled:      func(config *configuration.Config) bool { return config.ModsecEnabled },
			instanceName: func(config *configuration.Config) string { return config.ModsecInstanceName },
			prepare:      modsecurity.Prepare,
			open: func(bindCtx context.Context, config *configuration.Config, log *slog.Logger, traefikName string) error {
				_, err := modsecurity.Open(bindCtx, config, log, traefikName, pluginVersion)
				return err
			},
			ownershipKey: modsecurity.OwnershipKey,
			subscribe:    func(subscriptions *bouncer.Subscriptions) { subscriptions.ModSec = true },
			empty:        (*modsecurity.Client)(nil),
			receive:      func(route *bouncer.Bouncer) func(any) { return route.ReceiveModSec },
		},
		{
			group:        legRateLimit,
			enabled:      func(config *configuration.Config) bool { return config.RateLimitEnabled },
			instanceName: func(config *configuration.Config) string { return config.RateLimitInstanceName },
			prepare:      prepareRateLimit,
			open: func(bindCtx context.Context, config *configuration.Config, log *slog.Logger, traefikName string) error {
				_, err := ratelimit.Open(bindCtx, traefikName, rateLimitSettings(config), log)
				return err
			},
			ownershipKey: func(config *configuration.Config, traefikName string) string {
				return ratelimit.OwnershipKey(traefikName, rateLimitSettings(config))
			},
			subscribe: func(subscriptions *bouncer.Subscriptions) { subscriptions.RateLimit = true },
			empty:     (*ratelimit.Client)(nil),
			receive:   func(route *bouncer.Bouncer) func(any) { return route.ReceiveRateLimit },
		},
	}
}

// prepareRateLimit fills an omitted rateLimitInstanceName with the Traefik name and resolves the Redis
// password (file, then field) only when owned. It also returns a sync-rate parse error, so
// rateLimitSettings can build the Settings of an owner that got past prepare without one.
// It lives here, not in pkg/ratelimit, because pkg/configuration imports pkg/ratelimit.
func prepareRateLimit(config *configuration.Config, _ *slog.Logger, traefikName string) error {
	if !config.RateLimitEnabled {
		return nil
	}
	if strings.TrimSpace(config.RateLimitInstanceName) == "" {
		config.RateLimitInstanceName = traefikName
	}
	password, err := configuration.GetVariable(config, "RateLimitRedisPassword")
	if err != nil {
		return err
	}
	config.RateLimitRedisPassword = password
	_, err = configuration.RateLimitSyncRateDuration(config)
	return err
}

// rateLimitSettings is what the owner's config puts on its rate-limit Client: algorithm, Redis, buckets,
// policy, and instance name. Call it after prepareRateLimit, which resolved the password and parsed the sync rate.
func rateLimitSettings(config *configuration.Config) ratelimit.Settings {
	syncRate, _ := configuration.RateLimitSyncRateDuration(config) // prepareRateLimit returned its error
	return ratelimit.Settings{
		Algorithm:    config.RateLimitAlgorithm,
		Buckets:      config.RateLimitBuckets,
		InstanceName: config.RateLimitInstanceName,
		Policy: ratelimit.Policy{
			FailureAction:   configuration.EffectiveRateLimitFailureAction(config.RateLimitFailureAction),
			ResponseHeaders: config.RateLimitResponseHeaders,
			StatusCode:      config.RateLimitStatusCode,
		},
		Redis: ratelimit.RedisSettings{
			Database: config.RateLimitRedisDatabase,
			Host:     config.RateLimitRedisHost,
			Password: config.RateLimitRedisPassword,
			SyncRate: syncRate,
		},
	}
}

// subscribes reports whether this route bounces against leg: the router is on and an
// instance name is set. Owning is a different flag.
func (leg publishedLeg) subscribes(config *configuration.Config) bool {
	return config.BouncerEnabled && leg.instanceName(config) != ""
}

// instanceAlias is this plugin's opaque reclaim name for one published slot.
// Reclaim never parses it; SetAlias/ClearPublisher use group for rename and clear.
func instanceAlias(leg, instanceName string) string {
	if instanceName == "" {
		return ""
	}
	return "alias:" + leg + ":" + instanceName
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *configuration.Config {
	return configuration.New()
}

// New snapshots Traefik's config, Opens owned legs, publishes their instance names,
// and returns a Bouncer that ServeHTTP-Loads those names via Watch.
//
// lapiEnabled / appsecEnabled / captchaEnabled / modsecEnabled / rateLimitEnabled = own (Open + SetAlias).
// bouncerEnabled + a non-empty instance name = bounce (Watch). Those axes are independent.
// The rate-limit owner's Client carries its buckets and policy; a subscriber charges them under its own name.
//
// Open binds bindCtx, a child of Traefik's constructor ctx. The table has no Release:
// cancel bindCtx on a failed New so a half-built constructor does not leave a stream
// polling for the process lifetime. Success leaves bindCtx live; Traefik cancel of
// ctx still ends the holders.
func New(ctx context.Context, next http.Handler, rawConfig *configuration.Config, name string) (handler http.Handler, err error) {
	// Shallow copy: Config's []string and map[string]string fields still alias the caller's.
	config := *rawConfig
	config.LogLevel = strings.ToUpper(config.LogLevel)
	log := logger.NewWithFormat(config.LogLevel, config.LogFilePath, config.LogFormat)

	if err = configuration.ValidateParams(&config, log); err != nil {
		log.Error("New:validateParams", "error", err)
		return nil, err
	}
	// TODO: this has to go. Table grace is process-global (first New wins), not per slot.
	// E2e needed reclaimGraceSeconds=2 instead of ProcessGrace 30s so dispose is not the
	// production wait. Revisit when grace can be per incarnation or tests do not need this knob.
	reclaim.EnsureProcessGrace(time.Duration(config.ReclaimGraceSeconds) * time.Second)

	// Secrets plus omitted instance name → Traefik name, only when that leg is owned.
	legs := publishedLegs()
	for _, leg := range legs {
		if err = leg.prepare(&config, log, name); err != nil {
			return nil, err
		}
	}

	// Holder lease for everything this New Opens. Cancel only on error (named err).
	bindCtx, releaseHolders := context.WithCancel(ctx)
	defer func() {
		if err != nil {
			releaseHolders()
		}
	}()

	if err = openOwned(bindCtx, legs, &config, log, name); err != nil {
		return nil, err
	}
	if err = claimOwned(legs, &config, log, name); err != nil {
		return nil, err
	}

	// Bounce: the router is on and an instance name is set. Owning is a different flag.
	var subscriptions bouncer.Subscriptions
	for _, leg := range legs {
		if leg.subscribes(&config) {
			leg.subscribe(&subscriptions)
		}
	}
	route, err := bouncer.New(next, name, &config, subscriptions, log)
	if err != nil {
		return nil, err
	}
	for _, leg := range legs {
		if leg.subscribes(&config) {
			reclaim.Watch(ctx, instanceAlias(leg.group, leg.instanceName(&config)), leg.empty, leg.receive(route))
		}
	}
	// A leg Watch delivered nothing to has no connection: log it as Yaegi's typed-nil delivery would.
	route.TraceUndeliveredBindings()
	return route, nil
}

// openOwned is the own axis: Open each enabled leg on bindCtx, or ClearPublisher when
// this reconstruct dropped that flag (leftover alias would keep subscribers bound).
func openOwned(bindCtx context.Context, legs []publishedLeg, config *configuration.Config, log *slog.Logger, name string) error {
	for _, leg := range legs {
		if !leg.enabled(config) {
			reclaim.ClearPublisher(name, leg.group)
			continue
		}
		if err := leg.open(bindCtx, config, log, name); err != nil {
			return err
		}
	}
	return nil
}

// claimOwned publishes each owned instance name (SetAlias) to the Client Open just
// created. A taken name fails New. A later claim failure clears already-published
// legs so we do not leave a half-claimed owner. Order matches openOwned.
func claimOwned(legs []publishedLeg, config *configuration.Config, log *slog.Logger, name string) error {
	for claimIndex, leg := range legs {
		if !leg.enabled(config) {
			continue
		}
		if err := claimAlias(leg.ownershipKey(config, name), leg.group, leg.instanceName(config), name, log); err != nil {
			clearClaimedPublishers(legs[:claimIndex], config, name)
			return err
		}
	}
	return nil
}

// clearClaimedPublishers drops SetAlias for the enabled legs a failed claimOwned already published in this New.
func clearClaimedPublishers(claimedLegs []publishedLeg, config *configuration.Config, name string) {
	for _, leg := range claimedLegs {
		if leg.enabled(config) {
			reclaim.ClearPublisher(name, leg.group)
		}
	}
}

// claimAlias publishes instanceName on group for publisher, or logs and returns why the name is taken.
func claimAlias(key, group, instanceName, publisher string, log *slog.Logger) error {
	err := reclaim.SetAlias(key, instanceAlias(group, instanceName), publisher, group)
	if err != nil {
		log.Error("crowdsec instance name taken", "leg", group, "instanceName", instanceName, "rejected", publisher)
	}
	return err
}
