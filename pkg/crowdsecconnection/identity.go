package crowdsecconnection

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"strconv"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

const keyPrefix = "crowdsecconnection:"

// identity is the reclaim-key payload. Ban/captcha templates, trusted IPs,
// Enabled, middleware name, and log path are not included.
type identity struct {
	Mode                          string   `json:"mode"`
	LapiScheme                    string   `json:"lapiScheme"`
	LapiHost                      string   `json:"lapiHost"`
	LapiPath                      string   `json:"lapiPath"`
	LapiKey                       string   `json:"lapiKey"`
	CapiMachineID                 string   `json:"capiMachineId"`
	CapiPassword                  string   `json:"capiPassword"`
	CapiScenarios                 []string `json:"capiScenarios"`
	UpdateIntervalSeconds         int64    `json:"updateIntervalSeconds"`
	MetricsUpdateIntervalSeconds  int64    `json:"metricsUpdateIntervalSeconds"`
	UpdateMaxFailure              int64    `json:"updateMaxFailure"`
	LapiFailureAction             string   `json:"lapiFailureAction"`
	StreamStartupBlock            bool     `json:"streamStartupBlock"`
	DefaultDecisionSeconds        int64    `json:"defaultDecisionSeconds"`
	HTTPTimeoutSeconds            int64    `json:"httpTimeoutSeconds"`
	RedisCacheEnabled             bool     `json:"redisCacheEnabled"`
	RedisCacheHost                string   `json:"redisCacheHost"`
	RedisCacheReadHosts           []string `json:"redisCacheReadHosts"`
	RedisCachePassword            string   `json:"redisCachePassword"`
	RedisCacheDatabase            string   `json:"redisCacheDatabase"`
	RedisCacheUnreachableBlock    bool     `json:"redisCacheUnreachableBlock"`
	AppsecScheme                  string   `json:"appsecScheme"`
	AppsecHost                    string   `json:"appsecHost"`
	AppsecPath                    string   `json:"appsecPath"`
	AppsecKey                     string   `json:"appsecKey"`
	AppsecBodyLimit               int64    `json:"appsecBodyLimit"`
	AppsecTLSInsecureVerify       bool     `json:"appsecTlsInsecureVerify"`
	AppsecTLSCertificateAuthority string   `json:"appsecTlsCa"`
	AppsecTLSCertificateBouncer   string   `json:"appsecTlsCert"`
	LapiTLSInsecureVerify         bool     `json:"lapiTlsInsecureVerify"`
	LapiTLSCertificateAuthority   string   `json:"lapiTlsCa"`
	LapiTLSCertificateBouncer     string   `json:"lapiTlsCert"`
}

// identityFrom maps configuration.Config into reclaim identity fields.
func identityFrom(cfg *configuration.Config) identity {
	return identity{
		Mode:                          cfg.CrowdsecMode,
		LapiScheme:                    cfg.CrowdsecLapiScheme,
		LapiHost:                      cfg.CrowdsecLapiHost,
		LapiPath:                      cfg.CrowdsecLapiPath,
		LapiKey:                       cfg.CrowdsecLapiKey,
		CapiMachineID:                 cfg.CrowdsecCapiMachineID,
		CapiPassword:                  cfg.CrowdsecCapiPassword,
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
	}
}

// IdentityHex is the Redis key prefix and the hash suffix of the reclaim key.
func IdentityHex(cfg *configuration.Config) string {
	b, err := json.Marshal(identityFrom(cfg))
	if err != nil {
		return fmt.Sprint(cfg)
	}
	h := fnv.New64a()
	_, _ = h.Write(b)
	return strconv.FormatUint(h.Sum64(), 16)
}

// Key is the process reclaim table key for one CrowdsecConnection.
func Key(cfg *configuration.Config) string {
	return keyPrefix + IdentityHex(cfg)
}
