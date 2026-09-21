package lapi

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"strconv"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

const keyPrefix = "lapi:"

// identity is the live/none remaining-fields payload hashed into Key and IdentityHex.
// LapiMetricsIntervalSeconds stays so none/live routers that disagree get sibling
// Clients and each keeps its write-once metrics ticker. CAPI scenarios,
// lapiUpdateMaxFailure, and LapiUpdateIntervalSeconds stay omitted. Per-router policy,
// LapiStreamStartupBlock, HTTP timeout, and LAPI TLS are omitted so a reload of
// those knobs reuses the Client. Ban/captcha templates, BouncerDecisionRemap (Bouncer), trusted IPs, Enabled,
// middleware name, log path, and lapiScopeHeaders are not included here
// either (stream scopes= is poller-owned; live passes scopes per LiveLookup).
type identity struct {
	Mode                       string   `json:"mode"`
	LapiScheme                 string   `json:"lapiScheme"`
	LapiHost                   string   `json:"lapiHost"`
	LapiPath                   string   `json:"lapiPath"`
	LapiKey                    string   `json:"lapiKey"`
	CapiMachineID              string   `json:"capiMachineId"`
	CapiPassword               string   `json:"capiPassword"`
	LapiRedisEnabled           bool     `json:"lapiRedisEnabled"`
	LapiRedisHost              string   `json:"lapiRedisHost"`
	LapiRedisReadHosts         []string `json:"lapiRedisReadHosts"`
	LapiRedisPassword          string   `json:"lapiRedisPassword"`
	LapiRedisDatabase          string   `json:"lapiRedisDatabase"`
	LapiMetricsIntervalSeconds int64    `json:"lapiMetricsIntervalSeconds"`
}

// identityFrom maps configuration.Config into IdentityHex fields.
func identityFrom(cfg *configuration.Config) identity {
	return identity{
		Mode:                       cfg.LapiMode,
		LapiScheme:                 cfg.LapiScheme,
		LapiHost:                   cfg.LapiHost,
		LapiPath:                   cfg.LapiPath,
		LapiKey:                    cfg.LapiKey,
		CapiMachineID:              cfg.LapiCapiMachineID,
		CapiPassword:               cfg.LapiCapiPassword,
		LapiRedisEnabled:           cfg.LapiRedisEnabled,
		LapiRedisHost:              cfg.LapiRedisHost,
		LapiRedisReadHosts:         cfg.LapiRedisReadHosts,
		LapiRedisPassword:          cfg.LapiRedisPassword,
		LapiRedisDatabase:          cfg.LapiRedisDatabase,
		LapiMetricsIntervalSeconds: cfg.LapiMetricsIntervalSeconds,
	}
}

// hashBytes is FNV-64a hex used by IdentityHex and SessionHex.
func hashBytes(payload []byte) string {
	hasher := fnv.New64a()
	_, _ = hasher.Write(payload)
	return strconv.FormatUint(hasher.Sum64(), 16)
}

// IdentityHex is the exported hash of the live/none identity payload (not the Open suffix).
func IdentityHex(cfg *configuration.Config) string {
	b, err := json.Marshal(identityFrom(cfg))
	if err != nil {
		return fmt.Sprint(cfg)
	}
	return hashBytes(b)
}

// Key is the live/none Open key: SessionHex plus a hash of the identity payload
// (Redis store params and LapiMetricsIntervalSeconds). Stream SessionKey and
// StoreKey still omit the metrics interval.
func Key(cfg *configuration.Config) string {
	return keyPrefix + SessionHex(cfg) + ":" + hashJSON(identityFrom(cfg))
}
