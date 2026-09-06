package lapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

const streamSessionKeyPrefix = "lapi:stream:"

// streamSession is the CrowdSec-row identity for stream and alone modes.
// SessionPrefix / CachePrefix use only these fields. SessionKey appends a
// hash of streamSettings so a sleeping incarnation does not occupy the slot a
// reload with new knobs needs.
//
// CrowdSec LAPI does not give each HTTP client its own GET /v1/decisions/stream
// cursor. The cursor lives on the bouncer database row selected by:
//
//   - SHA-512 of the bouncer API key (X-Api-Key), and
//   - the client IP LAPI sees — this Traefik process’s outbound address, not
//     the visitor behind Traefik.
//
// scopes= on the query string is a filter of the same cursor, not a second
// cursor. Middleware name, metricsUpdateIntervalSeconds, Redis host, TLS
// extras, and decisionScopeHeaders are also not how LAPI picks the row.
// Usage-metrics POST uses that same authenticated row (`generated_by` =
// bouncer name, not payload name). Two metrics tickers on one key would be
// two windows for one CrowdSec bouncer; sharing the connection is required.
//
// Two in-process tickers that share scheme+host+path+key therefore share one
// CrowdSec row. Sequential startup=false polls steal deltas: each connection
// writes only the decisions that appeared in its own body. That looks like
// “stream cache is broken” (one router bans, the sibling does not). Isolated
// backends need a second bouncer key (or a different LAPI host), not a second
// ticker. Cross-process in-memory with the same LAPI-visible IP already shares
// that CrowdSec row; Redis is the multi-instance store. PeekLivePrefix on
// SessionPrefix finds a live sibling so those knobs cannot split the poller
// while another middleware still holds.
type streamSession struct {
	Mode          string `json:"mode"`
	LapiScheme    string `json:"lapiScheme"`
	LapiHost      string `json:"lapiHost"`
	LapiPath      string `json:"lapiPath"`
	LapiKey       string `json:"lapiKey"`
	CapiMachineID string `json:"capiMachineId"`
	CapiPassword  string `json:"capiPassword"`
}

// streamSettings is every former reclaim-hash field that is not streamSession.
//
// A second live middleware that disagrees is warn-and-wire: Traefik New must
// not fail the joiner router, and we must not start a second poller. The first
// New keeps intervals, Redis, TLS, and scopes=. Trusted IPs, ban/captcha
// templates, and AppSec stay off this LAPI session.
//
// A Traefik reload that changes this snapshot uses a new SessionKey. The old
// key is sleeping (tickers already off) until grace Close. Same snapshot: Open
// Wakes that key. Reclaim grace is only how long the slept object stays
// peekable, not a second poller.
//
// TLS extras are settings, not session, so a wrong LAPI client cert can be
// replaced on reload without a process restart. Two live middlewares with
// different certs still warn-and-wire (first wins) until the owner is gone.
type streamSettings struct {
	CapiScenarios                []string          `json:"capiScenarios"`
	UpdateIntervalSeconds        int64             `json:"updateIntervalSeconds"`
	MetricsUpdateIntervalSeconds int64             `json:"metricsUpdateIntervalSeconds"`
	UpdateMaxFailure             int64             `json:"updateMaxFailure"`
	LapiFailureAction            string            `json:"lapiFailureAction"`
	StreamStartupBlock           bool              `json:"streamStartupBlock"`
	DefaultDecisionSeconds       int64             `json:"defaultDecisionSeconds"`
	HTTPTimeoutSeconds           int64             `json:"httpTimeoutSeconds"`
	RedisCacheEnabled            bool              `json:"redisCacheEnabled"`
	RedisCacheHost               string            `json:"redisCacheHost"`
	RedisCacheReadHosts          []string          `json:"redisCacheReadHosts"`
	RedisCachePassword           string            `json:"redisCachePassword"`
	RedisCacheDatabase           string            `json:"redisCacheDatabase"`
	RedisCacheUnreachableBlock   bool              `json:"redisCacheUnreachableBlock"`
	LapiTLSInsecureVerify        bool              `json:"lapiTlsInsecureVerify"`
	LapiTLSCertificateAuthority  string            `json:"lapiTlsCa"`
	LapiTLSCertificateBouncer    string            `json:"lapiTlsCert"`
	DecisionScopeHeaders         map[string]string `json:"decisionScopeHeaders"`
}

// sessionFrom copies the CrowdSec-row fields off cfg. Call after Prepare.
func sessionFrom(cfg *configuration.Config) streamSession {
	return streamSession{
		Mode:          cfg.CrowdsecMode,
		LapiScheme:    cfg.CrowdsecLapiScheme,
		LapiHost:      cfg.CrowdsecLapiHost,
		LapiPath:      cfg.CrowdsecLapiPath,
		LapiKey:       cfg.CrowdsecLapiKey,
		CapiMachineID: cfg.CrowdsecCapiMachineID,
		CapiPassword:  cfg.CrowdsecCapiPassword,
	}
}

// settingsFrom copies the first-wins knobs off cfg. Call after Prepare.
func settingsFrom(cfg *configuration.Config) streamSettings {
	return streamSettings{
		CapiScenarios:                cfg.CrowdsecCapiScenarios,
		UpdateIntervalSeconds:        cfg.UpdateIntervalSeconds,
		MetricsUpdateIntervalSeconds: cfg.MetricsUpdateIntervalSeconds,
		UpdateMaxFailure:             cfg.UpdateMaxFailure,
		LapiFailureAction:            configuration.EffectiveFailureAction(cfg.CrowdsecLapiFailureAction),
		StreamStartupBlock:           cfg.StreamStartupBlock,
		DefaultDecisionSeconds:       cfg.DefaultDecisionSeconds,
		HTTPTimeoutSeconds:           cfg.HTTPTimeoutSeconds,
		RedisCacheEnabled:            cfg.RedisCacheEnabled,
		RedisCacheHost:               cfg.RedisCacheHost,
		RedisCacheReadHosts:          cfg.RedisCacheReadHosts,
		RedisCachePassword:           cfg.RedisCachePassword,
		RedisCacheDatabase:           cfg.RedisCacheDatabase,
		RedisCacheUnreachableBlock:   cfg.RedisCacheUnreachableBlock,
		LapiTLSInsecureVerify:        cfg.CrowdsecLapiTLSInsecureVerify,
		LapiTLSCertificateAuthority:  cfg.CrowdsecLapiTLSCertificateAuthority,
		LapiTLSCertificateBouncer:    cfg.CrowdsecLapiTLSCertificateBouncer,
		DecisionScopeHeaders:         decisionscope.NormalizeDecisionScopeHeaders(cfg.DecisionScopeHeaders),
	}
}

// hashJSON is FNV-64a of the JSON payload (same hasher as IdentityHex).
func hashJSON(payload any) string {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return fmt.Sprint(payload)
	}
	return hashBytes(encoded)
}

// SessionHex is the Redis/memory prefix for one stream session (LAPI URL+key).
func SessionHex(cfg *configuration.Config) string {
	return hashJSON(sessionFrom(cfg))
}

// SessionPrefix is the reclaim-key stem shared by every snapshot of one LAPI row.
func SessionPrefix(cfg *configuration.Config) string {
	return streamSessionKeyPrefix + SessionHex(cfg) + ":"
}

// SessionKey is the process reclaim table key: session prefix plus settings hash.
func SessionKey(cfg *configuration.Config) string {
	return SessionPrefix(cfg) + hashJSON(settingsFrom(cfg))
}

// CachePrefix is the cache Client prefix: session hex for stream/alone so
// warn-and-wire shares keys; full IdentityHex for live/none.
func CachePrefix(cfg *configuration.Config) string {
	if cfg.CrowdsecMode == configuration.StreamMode || cfg.CrowdsecMode == configuration.AloneMode {
		return SessionHex(cfg)
	}
	return IdentityHex(cfg)
}

// settingsDiff lists JSON field names that differ, for the warn-and-wire log.
func settingsDiff(owner, joiner streamSettings) []string {
	ownerFields := jsonObject(owner)
	joinerFields := jsonObject(joiner)
	names := map[string]struct{}{}
	for name := range ownerFields {
		names[name] = struct{}{}
	}
	for name := range joinerFields {
		names[name] = struct{}{}
	}
	var diff []string
	for name := range names {
		if fmt.Sprint(ownerFields[name]) != fmt.Sprint(joinerFields[name]) {
			diff = append(diff, name)
		}
	}
	sort.Strings(diff)
	return diff
}

// jsonObject is a map of JSON keys so settingsDiff can name ignored knobs.
func jsonObject(snapshot streamSettings) map[string]interface{} {
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return map[string]interface{}{}
	}
	fields := map[string]interface{}{}
	_ = json.Unmarshal(encoded, &fields)
	return fields
}

// warnWiredToOwner logs that this New will share the owner’s ticker and knobs.
func warnWiredToOwner(log *slog.Logger, ownerName, joinerName string, owner, joiner streamSettings) {
	fields := settingsDiff(owner, joiner)
	log.Warn("stream session already running for this LAPI URL+key (CrowdSec one cursor per bouncer row = hashed key + Traefik outbound IP); wiring this middleware to the existing stream instead of starting a second poller that would steal deltas",
		"ownerMiddleware", ownerName,
		"joiningMiddleware", joinerName,
		"ignoredSettings", strings.Join(fields, ","),
	)
}

// OpenStream reclaims one Client per stream session (LAPI URL+key).
//
// SessionKey is session prefix plus this snapshot’s hash. PeekLivePrefix on
// SessionPrefix finds another live middleware on the same CrowdSec row
// (streamOwner is who created that incarnation). Same snapshot → Open that
// key (Sleep/Wake across Traefik’s cancel-then-New gap). Live sibling with a
// different snapshot → warn-and-wire Open of their key. Sleeping leftover
// with a different snapshot is a different key: Open creates; the sleeper
// dies on grace Close.
func OpenStream(ctx context.Context, cfg *configuration.Config, log *slog.Logger, middlewareName, pluginVersion string) (*Client, error) {
	joinerKey := SessionKey(cfg)
	joinerSettings := settingsFrom(cfg)
	create := func() (any, error) {
		client, err := New(cfg, log, pluginVersion)
		if err != nil {
			return nil, err
		}
		client.streamOwner = middlewareName
		client.streamSettings = joinerSettings
		return wrappedClient(client), nil
	}

	bindKey := joinerKey
	live := reclaim.PeekLivePrefix(SessionPrefix(cfg))
	if live.OK && live.Key != joinerKey {
		existing, _ := live.Value.(*Client)
		if existing != nil {
			ownerName := existing.streamOwner
			if ownerName == "" {
				ownerName = "(unknown)"
			}
			warnWiredToOwner(log, ownerName, middlewareName, existing.streamSettings, joinerSettings)
		}
		bindKey = live.Key
	}

	sleeper := reclaim.Peek(bindKey)
	stored, openErr := reclaim.OpenWithGrace(ctx, bindKey, log, ReclaimGraceDuration, create)
	if openErr != nil {
		return nil, openErr
	}
	client, clientErr := clientFromStored(middlewareName, stored)
	if clientErr != nil {
		return nil, clientErr
	}
	// Sleeper belonged to another middleware that is gone. Take the name for later warnings.
	if sleeper.OK && sleeper.Holders == 0 && client.streamOwner != middlewareName {
		client.streamOwner = middlewareName
	}
	return client, nil
}

// OpenLive reclaims a Client by full identity (live/none).
func OpenLive(ctx context.Context, cfg *configuration.Config, log *slog.Logger, middlewareName, pluginVersion string) (*Client, error) {
	stored, openErr := reclaim.OpenWithGrace(ctx, Key(cfg), log, ReclaimGraceDuration, func() (any, error) {
		client, err := New(cfg, log, pluginVersion)
		if err != nil {
			return nil, err
		}
		return wrappedClient(client), nil
	})
	if openErr != nil {
		return nil, openErr
	}
	return clientFromStored(middlewareName, stored)
}

// wrappedClient is the reclaim create() result: funcs, not a type assert (Yaegi).
func wrappedClient(client *Client) *reclaim.Wrapped {
	return &reclaim.Wrapped{
		Value: client,
		Sleep: client.Sleep,
		Wake:  client.Wake,
		Close: client.Close,
	}
}

func clientFromStored(middlewareName string, stored any) (*Client, error) {
	client, ok := stored.(*Client)
	if !ok {
		return nil, fmt.Errorf("%s: reclaim: want *lapi.Client, got %T", middlewareName, stored)
	}
	return client, nil
}
