package crowdsecconnection

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

const streamSessionKeyPrefix = "crowdsecconnection:stream:"

// streamSession is the reclaim key for stream and alone modes.
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
// that CrowdSec row; Redis is the multi-instance store. This key omits
// intervals, Redis, TLS extras, AppSec, and decisionScopeHeaders so those
// knobs cannot split the poller.
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
// New keeps intervals, Redis, TLS, AppSec client, and scopes=. Trusted IPs and
// ban/captcha templates stay on the per-router Bouncer.
//
// A Traefik reload that changes this snapshot while the slot is sleeping
// ReplaceSleeping: the table Close()s the sleeper internally (tickers already
// off) then create()s a new HTTP client. Same snapshot: Open Wakes. Reclaim
// grace is only how long the slept object stays peekable, not a second poller.
//
// TLS extras are settings, not session, so a wrong LAPI client cert can be
// replaced on reload without a process restart. Two live middlewares with
// different certs still warn-and-wire (first wins) until the owner is gone.
type streamSettings struct {
	CapiScenarios                 []string          `json:"capiScenarios"`
	UpdateIntervalSeconds         int64             `json:"updateIntervalSeconds"`
	MetricsUpdateIntervalSeconds  int64             `json:"metricsUpdateIntervalSeconds"`
	UpdateMaxFailure              int64             `json:"updateMaxFailure"`
	LapiFailureAction             string            `json:"lapiFailureAction"`
	StreamStartupBlock            bool              `json:"streamStartupBlock"`
	DefaultDecisionSeconds        int64             `json:"defaultDecisionSeconds"`
	HTTPTimeoutSeconds            int64             `json:"httpTimeoutSeconds"`
	RedisCacheEnabled             bool              `json:"redisCacheEnabled"`
	RedisCacheHost                string            `json:"redisCacheHost"`
	RedisCacheReadHosts           []string          `json:"redisCacheReadHosts"`
	RedisCachePassword            string            `json:"redisCachePassword"`
	RedisCacheDatabase            string            `json:"redisCacheDatabase"`
	RedisCacheUnreachableBlock    bool              `json:"redisCacheUnreachableBlock"`
	AppsecScheme                  string            `json:"appsecScheme"`
	AppsecHost                    string            `json:"appsecHost"`
	AppsecPath                    string            `json:"appsecPath"`
	AppsecKey                     string            `json:"appsecKey"`
	AppsecBodyLimit               int64             `json:"appsecBodyLimit"`
	AppsecTLSInsecureVerify       bool              `json:"appsecTlsInsecureVerify"`
	AppsecTLSCertificateAuthority string            `json:"appsecTlsCa"`
	AppsecTLSCertificateBouncer   string            `json:"appsecTlsCert"`
	LapiTLSInsecureVerify         bool              `json:"lapiTlsInsecureVerify"`
	LapiTLSCertificateAuthority   string            `json:"lapiTlsCa"`
	LapiTLSCertificateBouncer     string            `json:"lapiTlsCert"`
	DecisionScopeHeaders          map[string]string `json:"decisionScopeHeaders"`
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
		CapiScenarios:                 cfg.CrowdsecCapiScenarios,
		UpdateIntervalSeconds:         cfg.UpdateIntervalSeconds,
		MetricsUpdateIntervalSeconds:  cfg.MetricsUpdateIntervalSeconds,
		UpdateMaxFailure:              cfg.UpdateMaxFailure,
		LapiFailureAction:             configuration.EffectiveFailureAction(cfg.CrowdsecLapiFailureAction),
		StreamStartupBlock:            cfg.StreamStartupBlock,
		DefaultDecisionSeconds:        cfg.DefaultDecisionSeconds,
		HTTPTimeoutSeconds:            cfg.HTTPTimeoutSeconds,
		RedisCacheEnabled:             cfg.RedisCacheEnabled,
		RedisCacheHost:                cfg.RedisCacheHost,
		RedisCacheReadHosts:           cfg.RedisCacheReadHosts,
		RedisCachePassword:            cfg.RedisCachePassword,
		RedisCacheDatabase:            cfg.RedisCacheDatabase,
		RedisCacheUnreachableBlock:    cfg.RedisCacheUnreachableBlock,
		AppsecScheme:                  cfg.CrowdsecAppsecScheme,
		AppsecHost:                    cfg.CrowdsecAppsecHost,
		AppsecPath:                    cfg.CrowdsecAppsecPath,
		AppsecKey:                     cfg.CrowdsecAppsecKey,
		AppsecBodyLimit:               cfg.CrowdsecAppsecBodyLimit,
		AppsecTLSInsecureVerify:       cfg.CrowdsecAppsecTLSInsecureVerify,
		AppsecTLSCertificateAuthority: cfg.CrowdsecAppsecTLSCertificateAuthority,
		AppsecTLSCertificateBouncer:   cfg.CrowdsecAppsecTLSCertificateBouncer,
		LapiTLSInsecureVerify:         cfg.CrowdsecLapiTLSInsecureVerify,
		LapiTLSCertificateAuthority:   cfg.CrowdsecLapiTLSCertificateAuthority,
		LapiTLSCertificateBouncer:     cfg.CrowdsecLapiTLSCertificateBouncer,
		DecisionScopeHeaders:          decisionscope.NormalizeDecisionScopeHeaders(cfg.DecisionScopeHeaders),
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

// SessionHex is the Redis/memory prefix and reclaim hash for one stream session.
func SessionHex(cfg *configuration.Config) string {
	return hashJSON(sessionFrom(cfg))
}

// SessionKey is the process reclaim table key for stream and alone.
func SessionKey(cfg *configuration.Config) string {
	return streamSessionKeyPrefix + SessionHex(cfg)
}

// CachePrefix is the cache Client prefix: session hex for stream/alone so
// warn-and-wire shares keys; full IdentityHex for live/none.
func CachePrefix(cfg *configuration.Config) string {
	if cfg.CrowdsecMode == configuration.StreamMode || cfg.CrowdsecMode == configuration.AloneMode {
		return SessionHex(cfg)
	}
	return IdentityHex(cfg)
}

// settingsEqual is true when both snapshots marshal to the same JSON.
func settingsEqual(owner, joiner streamSettings) bool {
	ownerJSON, ownerErr := json.Marshal(owner)
	joinerJSON, joinerErr := json.Marshal(joiner)
	if ownerErr != nil || joinerErr != nil {
		return false
	}
	return string(ownerJSON) == string(joinerJSON)
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

// OpenStream reclaims one CrowdsecConnection per stream session (LAPI URL+key).
//
// Peek the session without binding. streamOwner on the connection is who
// created this incarnation (not the reclaim key). Same snapshot → Open
// (Sleep/Wake across Traefik’s cancel-then-New gap). Live holders + different
// snapshot → warn-and-wire. Sleeping + different snapshot → ReplaceSleeping
// (table internally Close()s the sleeper; tickers already off).
func OpenStream(ctx context.Context, cfg *configuration.Config, log *slog.Logger, middlewareName, pluginVersion string) (*CrowdsecConnection, error) {
	sessionKey := SessionKey(cfg)
	joinerSettings := settingsFrom(cfg)
	create := func() (any, error) {
		conn, err := New(cfg, log, pluginVersion)
		if err != nil {
			return nil, err
		}
		conn.streamOwner = middlewareName
		conn.streamSettings = joinerSettings
		return conn, nil
	}

	peeked, holderCount, sleeping, found := reclaim.Peek(sessionKey)
	existing, _ := peeked.(*CrowdsecConnection)
	if found && existing != nil && !settingsEqual(existing.streamSettings, joinerSettings) {
		if holderCount > 0 {
			ownerName := existing.streamOwner
			if ownerName == "" {
				ownerName = "(unknown)"
			}
			warnWiredToOwner(log, ownerName, middlewareName, existing.streamSettings, joinerSettings)
		} else if sleeping {
			stored, err := reclaim.ReplaceSleeping(ctx, sessionKey, log, create)
			if err != nil {
				return nil, err
			}
			return streamConn(middlewareName, stored)
		}
	}

	stored, err := reclaim.Open(ctx, sessionKey, log, create)
	if err != nil {
		return nil, err
	}
	sessionConn, err := streamConn(middlewareName, stored)
	if err != nil {
		return nil, err
	}
	// Sleeper belonged to another middleware that is gone. Take the name for later warnings.
	if found && holderCount == 0 && sessionConn.streamOwner != middlewareName {
		sessionConn.streamOwner = middlewareName
	}
	return sessionConn, nil
}

// streamConn type-asserts the reclaim value to *CrowdsecConnection.
func streamConn(middlewareName string, stored any) (*CrowdsecConnection, error) {
	sessionConn, ok := stored.(*CrowdsecConnection)
	if !ok {
		return nil, fmt.Errorf("%s: reclaim: want *crowdsecconnection.CrowdsecConnection, got %T", middlewareName, stored)
	}
	return sessionConn, nil
}
