package lapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionstore"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

const streamSessionKeyPrefix = "lapi:stream:"
const msgStreamCollision = "crowdsec lapi stream collision"

// streamSession is the DecisionStore identity (SessionHex).
type streamSession struct {
	Mode                   string        `json:"mode"`
	LapiScheme             string        `json:"lapiScheme"`
	LapiHost               string        `json:"lapiHost"`
	LapiPath               string        `json:"lapiPath"`
	LapiKey                string        `json:"lapiKey"`
	CapiMachineID          string        `json:"capiMachineId"`
	CapiPassword           string        `json:"capiPassword"`
	DefaultDecisionSeconds int64         `json:"defaultDecisionSeconds"`
	StreamScopes           []string      `json:"streamScopes,omitempty"`
	Redis                  *sessionRedis `json:"redis,omitempty"`
}

type sessionRedis struct {
	Host      string   `json:"host"`
	ReadHosts []string `json:"readHosts"`
	Password  string   `json:"password"`
	Database  string   `json:"database"`
}

type streamOwnerIndex struct {
	mu     sync.Mutex
	owners map[string]map[string]struct{}
}

//nolint:gochecknoglobals // process-wide stream collision index for operator logs
var streamOwners = &streamOwnerIndex{owners: make(map[string]map[string]struct{})}

func sessionFrom(cfg *configuration.Config) streamSession {
	session := streamSession{
		Mode:                   cfg.CrowdsecMode,
		LapiScheme:             cfg.CrowdsecLapiScheme,
		LapiHost:               cfg.CrowdsecLapiHost,
		LapiPath:               cfg.CrowdsecLapiPath,
		LapiKey:                cfg.CrowdsecLapiKey,
		CapiMachineID:          cfg.CrowdsecCapiMachineID,
		CapiPassword:           cfg.CrowdsecCapiPassword,
		DefaultDecisionSeconds: cfg.DefaultDecisionSeconds,
	}
	if cfg.CrowdsecMode == configuration.StreamMode {
		session.StreamScopes = decisionscope.CanonicalStreamScopes(cfg.CrowdsecLapiStreamScopes)
	}
	if cfg.RedisCacheEnabled {
		session.Redis = &sessionRedis{
			Host:      cfg.RedisCacheHost,
			ReadHosts: sortedCopy(cfg.RedisCacheReadHosts),
			Password:  cfg.RedisCachePassword,
			Database:  cfg.RedisCacheDatabase,
		}
	}
	return session
}

func hashJSON(payload any) string {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return fmt.Sprint(payload)
	}
	return hashBytes(encoded)
}

// SessionHex is the Redis/memory prefix for one DecisionStore identity.
func SessionHex(cfg *configuration.Config) string {
	return hashJSON(sessionFrom(cfg))
}

// SessionPrefix is the reclaim-key stem shared by every Redis snapshot of one LAPI row.
func SessionPrefix(cfg *configuration.Config) string {
	return streamSessionKeyPrefix + SessionHex(cfg) + ":"
}

// SessionKey is session prefix plus Redis store-params hash (not the Client Open key).
func SessionKey(cfg *configuration.Config) string {
	return SessionPrefix(cfg) + hashJSON(storeParamsFrom(cfg))
}

func openDecisionStore(ctx context.Context, cfg *configuration.Config, log *slog.Logger, name string) (*decisionstore.Store, error) {
	return OpenDecisionStore(ctx, cfg, log, name)
}

// OpenStream reclaims one Client per ownership key (middleware name plus knobs).
func OpenStream(ctx context.Context, cfg *configuration.Config, log *slog.Logger, middlewareName, pluginVersion string) (*Client, error) {
	store, storeErr := openDecisionStore(ctx, cfg, log, middlewareName)
	if storeErr != nil {
		return nil, storeErr
	}
	bindKey := OwnershipKey(cfg, middlewareName)
	stored, openErr := reclaim.OpenWithHooks(ctx, bindKey, log, func() (any, reclaim.Hooks, error) {
		client, err := New(cfg, log, pluginVersion, store)
		if err != nil {
			return nil, reclaim.Hooks{}, err
		}
		client.middlewareName = middlewareName
		client.sessionKey = bindKey
		return client, clientHooks(client), nil
	})
	if openErr != nil {
		return nil, openErr
	}
	client, clientErr := clientFromStored(middlewareName, stored)
	if clientErr != nil {
		return nil, clientErr
	}
	client.middlewareName = middlewareName
	if client.sessionKey == "" {
		client.sessionKey = bindKey
	}
	noteStreamOwner(cfg, middlewareName, log)
	return client, nil
}

// OpenLive reclaims a Client by ownership key (live/none).
func OpenLive(ctx context.Context, cfg *configuration.Config, log *slog.Logger, middlewareName, pluginVersion string) (*Client, error) {
	store, storeErr := openDecisionStore(ctx, cfg, log, middlewareName)
	if storeErr != nil {
		return nil, storeErr
	}
	bindKey := OwnershipKey(cfg, middlewareName)
	stored, openErr := reclaim.OpenWithHooks(ctx, bindKey, log, func() (any, reclaim.Hooks, error) {
		client, err := New(cfg, log, pluginVersion, store)
		if err != nil {
			return nil, reclaim.Hooks{}, err
		}
		client.middlewareName = middlewareName
		client.sessionKey = bindKey
		return client, clientHooks(client), nil
	})
	if openErr != nil {
		return nil, openErr
	}
	client, clientErr := clientFromStored(middlewareName, stored)
	if clientErr != nil {
		return nil, clientErr
	}
	client.middlewareName = middlewareName
	if client.sessionKey == "" {
		client.sessionKey = bindKey
	}
	return client, nil
}

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

func streamOwnerKey(host, apiKey string) string {
	return host + "\x00" + apiKey
}

func noteStreamOwner(cfg *configuration.Config, middlewareName string, log *slog.Logger) {
	if cfg.CrowdsecMode != configuration.StreamMode && cfg.CrowdsecMode != configuration.AloneMode {
		return
	}
	if cfg.CrowdsecLapiKey == "" {
		return
	}
	key := streamOwnerKey(cfg.CrowdsecLapiHost, cfg.CrowdsecLapiKey)
	streamOwners.mu.Lock()
	defer streamOwners.mu.Unlock()
	if streamOwners.owners[key] == nil {
		streamOwners.owners[key] = make(map[string]struct{})
	}
	if _, self := streamOwners.owners[key][middlewareName]; !self && len(streamOwners.owners[key]) > 0 {
		existing := ""
		for name := range streamOwners.owners[key] {
			existing = name
			break
		}
		log.Warn(msgStreamCollision, "host", cfg.CrowdsecLapiHost, "publisher", existing, "other", middlewareName)
	}
	streamOwners.owners[key][middlewareName] = struct{}{}
}

func dropStreamOwner(host, apiKey, middlewareName string) {
	if apiKey == "" {
		return
	}
	key := streamOwnerKey(host, apiKey)
	streamOwners.mu.Lock()
	defer streamOwners.mu.Unlock()
	names := streamOwners.owners[key]
	if names == nil {
		return
	}
	delete(names, middlewareName)
	if len(names) == 0 {
		delete(streamOwners.owners, key)
	}
}
