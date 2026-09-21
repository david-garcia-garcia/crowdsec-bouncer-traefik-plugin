package lapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionstore"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

const streamSessionKeyPrefix = "lapi:stream:"

// streamSession is the CrowdSec-row identity for stream and alone modes.
// SessionPrefix and SessionHex use only these fields. SessionKey appends a
// hash of Redis store parameters so two Clients that share a cursor still
// isolate by Redis host. The DecisionStore key is SessionHex only.
//
// CrowdSec LAPI does not give each HTTP client its own GET /v1/decisions/stream
// cursor. The cursor lives on the bouncer database row selected by:
//
//   - SHA-512 of the bouncer API key (X-Api-Key), and
//   - the client IP LAPI sees — this Traefik process’s outbound address, not
//     the visitor behind Traefik.
//
// scopes= on the query string is a filter of the same cursor, not a second
// cursor. Intervals, CAPI scenarios, lapiUpdateMaxFailure, and lapiScopeHeaders
// are also not how LAPI picks the row. Usage-metrics POST uses that same
// authenticated row (`generated_by` = bouncer name, not payload name).
//
// Two in-process tickers that share scheme+host+path+key therefore share one
// CrowdSec row. Sequential startup=false polls steal deltas: each connection
// writes only the decisions that appeared in its own body. Isolated backends
// need a second bouncer key (or a different LAPI host), not a second ticker.
// Cross-process in-memory with the same LAPI-visible IP already shares that
// CrowdSec row; Redis is the multi-instance store.
//
// Upgrade: SessionHex and store Redis params stay. Existing Redis keys stay
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
		Mode:          cfg.LapiMode,
		LapiScheme:    cfg.LapiScheme,
		LapiHost:      cfg.LapiHost,
		LapiPath:      cfg.LapiPath,
		LapiKey:       cfg.LapiKey,
		CapiMachineID: cfg.LapiCapiMachineID,
		CapiPassword:  cfg.LapiCapiPassword,
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

// SessionPrefix is the reclaim-key stem shared by every Redis snapshot of one LAPI row.
func SessionPrefix(cfg *configuration.Config) string {
	return streamSessionKeyPrefix + SessionHex(cfg) + ":"
}

// SessionKey is the stream/alone Open key: session prefix plus Redis store-params hash.
func SessionKey(cfg *configuration.Config) string {
	return SessionPrefix(cfg) + hashJSON(storeParamsFrom(cfg))
}

// reclaimSessionKey is SessionKey for stream/alone and Key for live/none.
func reclaimSessionKey(cfg *configuration.Config) string {
	if cfg.LapiMode == configuration.StreamMode || cfg.LapiMode == configuration.AloneMode {
		return SessionKey(cfg)
	}
	return Key(cfg)
}

// rejectForeignStoreOwner Peeks the DecisionStore key and fails when another Traefik name owns it.
func rejectForeignStoreOwner(log *slog.Logger, storeKey, name string) error {
	value, _, ok := reclaim.Peek(storeKey)
	if !ok {
		return nil
	}
	store, isStore := value.(*decisionstore.Store)
	if !isStore {
		return nil
	}
	owner := store.CreatedBy()
	if owner == name {
		return nil
	}
	log.Error("lapi session exclusive: DecisionStore already owned",
		"owner", owner,
		"rejected", name,
		"clears", "when the old slot Closes",
		"isolation", "a second bouncer API key (or a different LAPI host), not a second middleware on the same key",
	)
	return fmt.Errorf("lapi session exclusive: store owned by %q, rejected %q; lock clears when the old slot Closes; isolation is a second bouncer API key (or a different LAPI host), not a second middleware on the same key", owner, name)
}

// openDecisionStoreExclusive Peeks then Opens the SessionHex store for this Traefik name.
func openDecisionStoreExclusive(ctx context.Context, cfg *configuration.Config, log *slog.Logger, name string) (*decisionstore.Store, error) {
	if err := rejectForeignStoreOwner(log, StoreKey(cfg), name); err != nil {
		return nil, err
	}
	return OpenDecisionStore(ctx, cfg, log, name)
}

// OpenStream reclaims one Client per cursor plus Redis (LAPI URL+key).
//
// SessionKey is session prefix plus this Redis snapshot’s hash. Same Redis
// snapshot → Open that key (Sleep/Wake across Traefik’s cancel-then-New gap),
// even when intervals, CAPI scenarios, lapiUpdateMaxFailure, or header maps differ.
// A different Redis host is a different Client key and the same DecisionStore
// when the Traefik name matches. Interval / CAPI / lapiUpdateMaxFailure
// mismatch on a live sibling is silent first-wins (create already wrote those
// scalars). A different Traefik name on the same SessionHex fails before Open.
// After bind, this constructor registers its header scopes.
func OpenStream(ctx context.Context, cfg *configuration.Config, log *slog.Logger, middlewareName, pluginVersion string) (*Client, error) {
	store, storeErr := openDecisionStoreExclusive(ctx, cfg, log, middlewareName)
	if storeErr != nil {
		return nil, storeErr
	}
	bindKey := SessionKey(cfg)
	stored, openErr := reclaim.OpenWithHooks(ctx, bindKey, log, func() (any, reclaim.Hooks, error) {
		client, err := New(cfg, log, pluginVersion, store)
		if err != nil {
			return nil, reclaim.Hooks{}, err
		}
		return client, clientHooks(client), nil
	})
	if openErr != nil {
		return nil, openErr
	}
	client, clientErr := clientFromStored(middlewareName, stored)
	if clientErr != nil {
		return nil, clientErr
	}
	// sessionKey is write-once in New; Wake may already be polling.
	replaced, adoptErr := client.AdoptTransport(cfg)
	if adoptErr != nil {
		return nil, adoptErr
	}
	client.registerLiveHeaderScopes(ctx, decisionscope.NormalizeLapiScopeHeaders(cfg.LapiScopeHeaders))
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
	store, storeErr := openDecisionStoreExclusive(ctx, cfg, log, middlewareName)
	if storeErr != nil {
		return nil, storeErr
	}
	bindKey := Key(cfg)
	stored, openErr := reclaim.OpenWithHooks(ctx, bindKey, log, func() (any, reclaim.Hooks, error) {
		client, err := New(cfg, log, pluginVersion, store)
		if err != nil {
			return nil, reclaim.Hooks{}, err
		}
		return client, clientHooks(client), nil
	})
	if openErr != nil {
		return nil, openErr
	}
	client, clientErr := clientFromStored(middlewareName, stored)
	if clientErr != nil {
		return nil, clientErr
	}
	// sessionKey is write-once in New; Wake may already be polling.
	replaced, adoptErr := client.AdoptTransport(cfg)
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
