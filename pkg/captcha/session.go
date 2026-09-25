package captcha

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

const ownerKeyPrefix = "captcha:owner:"

// ownership is the captcha Open-key payload: middleware name plus instance-owned knobs, including log config.
// Slot name, bounce, failure actions, remediation header, and startup-block stay off it.
type ownership struct {
	MiddlewareName               string `json:"middlewareName"`
	Provider                     string `json:"provider"`
	SiteKey                      string `json:"siteKey"`
	SecretKey                    string `json:"secretKey"`
	GateSecret                   string `json:"gateSecret"`
	GateBindIP                   bool   `json:"gateBindIp"`
	CaptchaFilePath              string `json:"captchaFilePath"`
	GracePeriodSeconds           int64  `json:"gracePeriodSeconds"`
	SiteverifyHTTPTimeoutSeconds int64  `json:"siteverifyHttpTimeoutSeconds"`
	CustomJsURL                  string `json:"customJsUrl"`
	CustomChallengeURL           string `json:"customChallengeUrl"`
	CustomKey                    string `json:"customKey"`
	CustomResponse               string `json:"customResponse"`
	CustomValidateURL            string `json:"customValidateUrl"`
	CustomValidateBody           string `json:"customValidateBody"`
	EnterpriseAction             string `json:"enterpriseAction"`
	EnterpriseAPIKey             string `json:"enterpriseApiKey"`
	EnterpriseKeyType            string `json:"enterpriseKeyType"`
	EnterpriseMinScore           string `json:"enterpriseMinScore"`
	EnterpriseProjectID          string `json:"enterpriseProjectId"`
	LogFilePath                  string `json:"logFilePath"`
	LogFormat                    string `json:"logFormat"`
	LogLevel                     string `json:"logLevel"`
}

func ownershipFrom(cfg *configuration.Config, middlewareName string) ownership {
	siteKey, _ := configuration.GetVariable(cfg, "CaptchaSiteKey")
	secretKey, _ := configuration.GetVariable(cfg, "CaptchaSecretKey")
	gateSecret, _ := configuration.GetVariable(cfg, "CaptchaGateSecret")
	enterpriseAPIKey, _ := configuration.GetVariable(cfg, "CaptchaEnterpriseAPIKey")
	return ownership{
		MiddlewareName:               middlewareName,
		Provider:                     cfg.CaptchaProvider,
		SiteKey:                      siteKey,
		SecretKey:                    secretKey,
		GateSecret:                   gateSecret,
		GateBindIP:                   cfg.CaptchaGateBindIP,
		CaptchaFilePath:              cfg.CaptchaFilePath,
		GracePeriodSeconds:           cfg.CaptchaGracePeriodSeconds,
		SiteverifyHTTPTimeoutSeconds: cfg.CaptchaSiteverifyHTTPTimeoutSeconds,
		CustomJsURL:                  cfg.CaptchaCustomJsURL,
		CustomChallengeURL:           cfg.CaptchaCustomChallengeURL,
		CustomKey:                    cfg.CaptchaCustomKey,
		CustomResponse:               cfg.CaptchaCustomResponse,
		CustomValidateURL:            cfg.CaptchaCustomValidateURL,
		CustomValidateBody:           cfg.CaptchaCustomValidateBody,
		EnterpriseAction:             cfg.CaptchaEnterpriseAction,
		EnterpriseAPIKey:             enterpriseAPIKey,
		EnterpriseKeyType:            cfg.CaptchaEnterpriseKeyType,
		EnterpriseMinScore:           cfg.CaptchaEnterpriseMinScore,
		EnterpriseProjectID:          cfg.CaptchaEnterpriseProjectID,
		LogFilePath:                  cfg.LogFilePath,
		LogFormat:                    cfg.LogFormat,
		LogLevel:                     cfg.LogLevel,
	}
}

func hashBytes(payload []byte) string {
	hasher := fnv.New64a()
	_, _ = hasher.Write(payload)
	return strconv.FormatUint(hasher.Sum64(), 16)
}

func hashJSON(payload any) string {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return fmt.Sprint(payload)
	}
	return hashBytes(encoded)
}

// Prepare fills an omitted captcha instance name with the Traefik name only when owned.
func Prepare(cfg *configuration.Config, _ *slog.Logger, traefikName string) error {
	if cfg.CaptchaEnabled && strings.TrimSpace(cfg.CaptchaInstanceName) == "" {
		cfg.CaptchaInstanceName = traefikName
	}
	return nil
}

// OwnershipKey is the captcha Client reclaim Open key: middleware name plus owner knobs.
func OwnershipKey(cfg *configuration.Config, middlewareName string) string {
	return ownerKeyPrefix + hashJSON(ownershipFrom(cfg, middlewareName))
}

// Open reclaims a captcha Client by middleware name plus instance-owned knobs.
func Open(ctx context.Context, cfg *configuration.Config, log *slog.Logger, middlewareName, pluginVersion string) (*Client, error) {
	bindKey := OwnershipKey(cfg, middlewareName)
	stored, openErr := reclaim.OpenWithHooks(ctx, bindKey, log, func() (any, reclaim.Hooks, error) {
		client, err := newOwnerClient(cfg, log, middlewareName, bindKey, pluginVersion)
		if err != nil {
			return nil, reclaim.Hooks{}, err
		}
		return client, reclaim.Hooks{Sleep: client.Sleep, Wake: client.Wake, Close: client.Close}, nil
	})
	if openErr != nil {
		return nil, openErr
	}
	client, ok := stored.(*Client)
	if !ok {
		return nil, fmt.Errorf("%s: reclaim: want *captcha.Client, got %T", middlewareName, stored)
	}
	client.bindIdentity(middlewareName, bindKey)
	return client, nil
}

// newOwnerClient constructs the captcha Client (widget, verifier, template, gate) for one owner Open.
func newOwnerClient(cfg *configuration.Config, log *slog.Logger, middlewareName, bindKey, _ string) (*Client, error) {
	siteKey, _ := configuration.GetVariable(cfg, "CaptchaSiteKey")
	secretKey, _ := configuration.GetVariable(cfg, "CaptchaSecretKey")
	gateSecret, _ := configuration.GetVariable(cfg, "CaptchaGateSecret")
	enterpriseAPIKey, _ := configuration.GetVariable(cfg, "CaptchaEnterpriseAPIKey")
	log = log.With(
		"traefikName", middlewareName,
		"instanceName", cfg.CaptchaInstanceName,
		"leg", "captcha",
		"sessionKey", bindKey,
	)
	client := &Client{}
	err := client.New(
		log,
		&http.Client{
			Transport: &http.Transport{MaxIdleConns: 10, MaxIdleConnsPerHost: 10, IdleConnTimeout: 30 * time.Second},
			Timeout:   time.Duration(cfg.CaptchaSiteverifyHTTPTimeoutSeconds) * time.Second,
		},
		cfg.CaptchaProvider,
		cfg.CaptchaCustomJsURL,
		cfg.CaptchaCustomChallengeURL,
		cfg.CaptchaCustomKey,
		cfg.CaptchaCustomResponse,
		cfg.CaptchaCustomValidateURL,
		cfg.CaptchaCustomValidateBody,
		siteKey,
		secretKey,
		gateSecret,
		cfg.CaptchaGateBindIP,
		cfg.CaptchaFilePath,
		cfg.CaptchaGracePeriodSeconds,
		Enterprise{
			Action:    cfg.CaptchaEnterpriseAction,
			APIKey:    enterpriseAPIKey,
			KeyType:   cfg.CaptchaEnterpriseKeyType,
			MinScore:  cfg.CaptchaEnterpriseMinScore,
			ProjectID: cfg.CaptchaEnterpriseProjectID,
		},
	)
	if err != nil {
		return nil, err
	}
	client.middlewareName = middlewareName
	client.instanceName = cfg.CaptchaInstanceName
	client.sessionKey = bindKey
	client.incarnation = fmt.Sprintf("%p", client)
	client.log.Info("crowdsec captcha instance started", "incarnation", client.incarnation, "reason", "started")
	return client, nil
}
