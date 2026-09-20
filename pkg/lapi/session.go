package lapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

const streamSessionKeyPrefix = "lapi:stream:"

// streamSession is the CrowdSec-row identity for stream and alone modes.
// SessionHex and SessionKey use only these fields. Redis store parameters
// are not in the Open key: two Clients that share a cursor share one ticker.
//
// CrowdSec LAPI does not give each HTTP client its own GET /v1/decisions/stream
// cursor. The cursor lives on the bouncer database row selected by:
//
//   - SHA-512 of the bouncer API key (X-Api-Key), and
//   - the client IP LAPI sees — this Traefik process’s outbound address, not
//     the visitor behind Traefik.
//
// scopes= on the query string is a filter of the same cursor, not a second
// cursor. Intervals, CAPI scenarios, updateMaxFailure, decisionScopeHeaders,
// Redis, middleware name, and outbound IP are also not how LAPI picks the row.
// Usage-metrics POST uses that same authenticated row (`generated_by` = bouncer
// name, not payload name).
//
// Two in-process tickers that share scheme+host+path+key therefore share one
// CrowdSec row. Sequential startup=false polls steal deltas: each connection
// writes only the decisions that appeared in its own body. Isolated backends
// need a second bouncer key (or a different LAPI host), not a second ticker.
// Cross-process in-memory with the same LAPI-visible IP already shares that
// CrowdSec row; Redis is the multi-instance store.
//
// Upgrade: SessionHex stays the Redis key prefix. Existing Redis keys stay
// reachable. Changing the Client Open string only renames the in-process table
// key. No Redis key migration.
type streamSession struct {
	Mode          string `json:"mode"`
	LapiScheme    string `json:"lapiScheme"`
	LapiHost      string `json:"lapiHost"`
	LapiPath      string `json:"lapiPath"`
	LapiKey       string `json:"lapiKey"`
	CapiMachineID string `json:"capiMachineId"`
	CapiPassword  string `json:"capiPassword"`
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

// SessionKey is the stream/alone Open key: lapi:stream: plus SessionHex.
func SessionKey(cfg *configuration.Config) string {
	return streamSessionKeyPrefix + SessionHex(cfg)
}

// reclaimSessionKey is SessionKey for stream/alone and Key for live/none.
func reclaimSessionKey(cfg *configuration.Config) string {
	if cfg.CrowdsecMode == configuration.StreamMode || cfg.CrowdsecMode == configuration.AloneMode {
		return SessionKey(cfg)
	}
	return Key(cfg)
}

// OpenStream reclaims one Client per LAPI session (URL+key, mode).
//
// SessionKey is lapi:stream: plus SessionHex. Same session → Open that key
// (Sleep/Wake across Traefik’s cancel-then-New gap), even when Redis, intervals,
// CAPI scenarios, updateMaxFailure, or header maps differ. Redis / interval /
// CAPI / updateMaxFailure mismatch on a live sibling or Wake is first-wins with
// WARN. After bind, this constructor registers its header scopes and holder name.
func OpenStream(ctx context.Context, cfg *configuration.Config, log *slog.Logger, middlewareName, pluginVersion string) (*Client, error) {
	bindKey := SessionKey(cfg)
	client, created, openErr := openClient(ctx, bindKey, cfg, log, middlewareName, pluginVersion)
	if openErr != nil {
		return nil, openErr
	}
	replaced, adoptErr := adoptRegisterAndWarn(ctx, client, cfg, middlewareName, !created)
	if adoptErr != nil {
		return nil, adoptErr
	}
	client.registerLiveHeaderScopes(ctx, decisionscope.NormalizeDecisionScopeHeaders(cfg.DecisionScopeHeaders))
	if replaced {
		log.Info("lapi session joiner adopted",
			"sessionKey", bindKey,
			"joiningMiddleware", middlewareName,
		)
	}
	return client, nil
}

// OpenLive reclaims a Client by cursor plus Redis and metrics interval (live/none).
func OpenLive(ctx context.Context, cfg *configuration.Config, log *slog.Logger, middlewareName, pluginVersion string) (*Client, error) {
	bindKey := Key(cfg)
	client, created, openErr := openClient(ctx, bindKey, cfg, log, middlewareName, pluginVersion)
	if openErr != nil {
		return nil, openErr
	}
	replaced, adoptErr := adoptRegisterAndWarn(ctx, client, cfg, middlewareName, !created)
	if adoptErr != nil {
		return nil, adoptErr
	}
	if replaced {
		log.Info("lapi session joiner adopted",
			"sessionKey", bindKey,
			"joiningMiddleware", middlewareName,
		)
	}
	return client, nil
}

// openClient reclaims or creates a Client for bindKey. created is true when this Open ran create().
func openClient(ctx context.Context, bindKey string, cfg *configuration.Config, log *slog.Logger, middlewareName, pluginVersion string) (*Client, bool, error) {
	created := false
	stored, openErr := reclaim.OpenWithHooks(ctx, bindKey, log, func() (any, reclaim.Hooks, error) {
		created = true
		client, err := New(cfg, log, pluginVersion)
		if err != nil {
			return nil, reclaim.Hooks{}, err
		}
		return client, clientHooks(client), nil
	})
	if openErr != nil {
		return nil, created, openErr
	}
	client, clientErr := clientFromStored(middlewareName, stored)
	if clientErr != nil {
		return nil, created, clientErr
	}
	client.sessionKey = bindKey
	return client, created, nil
}

// adoptRegisterAndWarn adopts transport, records the middleware name, and WARNs session-owned mismatch on join/Wake.
func adoptRegisterAndWarn(ctx context.Context, client *Client, cfg *configuration.Config, middlewareName string, reused bool) (bool, error) {
	replaced, adoptErr := client.AdoptTransport(cfg)
	if adoptErr != nil {
		return false, adoptErr
	}
	client.registerLiveMiddlewareName(ctx, middlewareName)
	if reused {
		client.warnIgnoredSessionOwned(cfg)
	}
	return replaced, nil
}

// clientHooks is Sleep/Wake/Close as funcs: Yaegi panics on asserting a foreign concrete type.
func clientHooks(client *Client) reclaim.Hooks {
	return reclaim.Hooks{Sleep: client.Sleep, Wake: client.Wake, Close: client.Close}
}

func clientFromStored(middlewareName string, stored any) (*Client, error) {
	client, ok := stored.(*Client)
	if !ok {
		return nil, fmt.Errorf("%s: reclaim: want *lapi.Client, got %T", middlewareName, stored)
	}
	return client, nil
}
