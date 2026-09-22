package lapi

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"sort"
	"strconv"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
)

const keyPrefix = "lapi:"
const ownerKeyPrefix = "lapi:owner:"

// identity is the live/none remaining-fields payload hashed into IdentityHex.
// Middleware name, timeout, and TLS live on OwnershipKey, not here.
type identity struct {
	Mode                         string   `json:"mode"`
	LapiScheme                   string   `json:"lapiScheme"`
	LapiHost                     string   `json:"lapiHost"`
	LapiPath                     string   `json:"lapiPath"`
	LapiKey                      string   `json:"lapiKey"`
	CapiMachineID                string   `json:"capiMachineId"`
	CapiPassword                 string   `json:"capiPassword"`
	RedisCacheEnabled            bool     `json:"redisCacheEnabled"`
	RedisCacheHost               string   `json:"redisCacheHost"`
	RedisCacheReadHosts          []string `json:"redisCacheReadHosts"`
	RedisCachePassword           string   `json:"redisCachePassword"`
	RedisCacheDatabase           string   `json:"redisCacheDatabase"`
	MetricsUpdateIntervalSeconds int64    `json:"metricsUpdateIntervalSeconds"`
}

type ownership struct {
	MiddlewareName               string   `json:"middlewareName"`
	Mode                         string   `json:"mode"`
	LapiScheme                   string   `json:"lapiScheme"`
	LapiHost                     string   `json:"lapiHost"`
	LapiPath                     string   `json:"lapiPath"`
	LapiKey                      string   `json:"lapiKey"`
	TLSInsecureVerify            bool     `json:"tlsInsecureVerify"`
	TLSCertificateAuthority      string   `json:"tlsCertificateAuthority"`
	TLSCertificateBouncer        string   `json:"tlsCertificateBouncer"`
	TLSCertificateBouncerKey     string   `json:"tlsCertificateBouncerKey"`
	HTTPTimeoutSeconds           int64    `json:"httpTimeoutSeconds"`
	RedisCacheEnabled            bool     `json:"redisCacheEnabled"`
	RedisCacheHost               string   `json:"redisCacheHost"`
	RedisCacheReadHosts          []string `json:"redisCacheReadHosts"`
	RedisCachePassword           string   `json:"redisCachePassword"`
	RedisCacheDatabase           string   `json:"redisCacheDatabase"`
	StreamScopes                 []string `json:"streamScopes"`
	CapiMachineID                string   `json:"capiMachineId"`
	CapiPassword                 string   `json:"capiPassword"`
	UpdateIntervalSeconds        int64    `json:"updateIntervalSeconds"`
	MetricsUpdateIntervalSeconds int64    `json:"metricsUpdateIntervalSeconds"`
	UpdateMaxFailure             int64    `json:"updateMaxFailure"`
	CrowdsecCapiScenarios        []string `json:"crowdsecCapiScenarios"`
	DefaultDecisionSeconds       int64    `json:"defaultDecisionSeconds"`
}

func identityFrom(cfg *configuration.Config) identity {
	return identity{
		Mode:                         cfg.CrowdsecMode,
		LapiScheme:                   cfg.CrowdsecLapiScheme,
		LapiHost:                     cfg.CrowdsecLapiHost,
		LapiPath:                     cfg.CrowdsecLapiPath,
		LapiKey:                      cfg.CrowdsecLapiKey,
		CapiMachineID:                cfg.CrowdsecCapiMachineID,
		CapiPassword:                 cfg.CrowdsecCapiPassword,
		RedisCacheEnabled:            cfg.RedisCacheEnabled,
		RedisCacheHost:               cfg.RedisCacheHost,
		RedisCacheReadHosts:          sortedCopy(cfg.RedisCacheReadHosts),
		RedisCachePassword:           cfg.RedisCachePassword,
		RedisCacheDatabase:           cfg.RedisCacheDatabase,
		MetricsUpdateIntervalSeconds: cfg.MetricsUpdateIntervalSeconds,
	}
}

func ownershipFrom(cfg *configuration.Config, middlewareName string) ownership {
	ca, _ := configuration.GetVariable(cfg, "CrowdsecLapiTLSCertificateAuthority")
	cert, _ := configuration.GetVariable(cfg, "CrowdsecLapiTLSCertificateBouncer")
	certKey, _ := configuration.GetVariable(cfg, "CrowdsecLapiTLSCertificateBouncerKey")
	return ownership{
		MiddlewareName:               middlewareName,
		Mode:                         cfg.CrowdsecMode,
		LapiScheme:                   cfg.CrowdsecLapiScheme,
		LapiHost:                     cfg.CrowdsecLapiHost,
		LapiPath:                     cfg.CrowdsecLapiPath,
		LapiKey:                      cfg.CrowdsecLapiKey,
		TLSInsecureVerify:            cfg.CrowdsecLapiTLSInsecureVerify,
		TLSCertificateAuthority:      ca,
		TLSCertificateBouncer:        cert,
		TLSCertificateBouncerKey:     certKey,
		HTTPTimeoutSeconds:           cfg.EffectiveHTTPTimeoutSeconds(cfg.CrowdsecLapiHTTPTimeoutSeconds),
		RedisCacheEnabled:            cfg.RedisCacheEnabled,
		RedisCacheHost:               cfg.RedisCacheHost,
		RedisCacheReadHosts:          sortedCopy(cfg.RedisCacheReadHosts),
		RedisCachePassword:           cfg.RedisCachePassword,
		RedisCacheDatabase:           cfg.RedisCacheDatabase,
		StreamScopes:                 decisionscope.CanonicalStreamScopes(cfg.CrowdsecLapiStreamScopes),
		CapiMachineID:                cfg.CrowdsecCapiMachineID,
		CapiPassword:                 cfg.CrowdsecCapiPassword,
		UpdateIntervalSeconds:        cfg.UpdateIntervalSeconds,
		MetricsUpdateIntervalSeconds: cfg.MetricsUpdateIntervalSeconds,
		UpdateMaxFailure:             cfg.UpdateMaxFailure,
		CrowdsecCapiScenarios:        append([]string(nil), cfg.CrowdsecCapiScenarios...),
		DefaultDecisionSeconds:       cfg.DefaultDecisionSeconds,
	}
}

func sortedCopy(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

func hashBytes(payload []byte) string {
	hasher := fnv.New64a()
	_, _ = hasher.Write(payload)
	return strconv.FormatUint(hasher.Sum64(), 16)
}

// IdentityHex is the exported hash of the live/none identity payload (not the Open suffix).
func IdentityHex(cfg *configuration.Config) string {
	encoded, err := json.Marshal(identityFrom(cfg))
	if err != nil {
		return fmt.Sprint(cfg)
	}
	return hashBytes(encoded)
}

// OwnershipKey is the LAPI Client reclaim Open key: middleware name plus client knobs.
func OwnershipKey(cfg *configuration.Config, middlewareName string) string {
	return ownerKeyPrefix + hashJSON(ownershipFrom(cfg, middlewareName))
}

// Key is the live/none Open key without middleware name (store-adjacent identity).
func Key(cfg *configuration.Config) string {
	return keyPrefix + SessionHex(cfg) + ":" + hashJSON(identityFrom(cfg))
}
