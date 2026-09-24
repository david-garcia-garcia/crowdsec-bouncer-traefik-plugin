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

// MsgInstanceStarted is the INFO create line for one captcha Client incarnation.
const MsgInstanceStarted = "crowdsec captcha instance started"

// MsgInstanceSleeping is the DEBUG line when the last holder leaves.
const MsgInstanceSleeping = "crowdsec captcha instance sleeping"

// MsgInstanceWaking is the DEBUG line when a holder binds again.
const MsgInstanceWaking = "crowdsec captcha instance waking"

// MsgInstanceClosed is the INFO line when the Client incarnation is closed.
const MsgInstanceClosed = "crowdsec captcha instance closed"

// ownership is the captcha Open-key payload: middleware name plus instance-owned knobs.
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
}

func ownershipFrom(cfg *configuration.Config, middlewareName string) ownership {
	siteKey, _ := configuration.GetVariable(cfg, "BouncerCaptchaSiteKey")
	secretKey, _ := configuration.GetVariable(cfg, "BouncerCaptchaSecretKey")
	gateSecret, _ := configuration.GetVariable(cfg, "BouncerCaptchaGateSecret")
	return ownership{
		MiddlewareName:               middlewareName,
		Provider:                     cfg.BouncerCaptchaProvider,
		SiteKey:                      siteKey,
		SecretKey:                    secretKey,
		GateSecret:                   gateSecret,
		GateBindIP:                   cfg.BouncerCaptchaGateBindIP,
		CaptchaFilePath:              cfg.BouncerCaptchaFilePath,
		GracePeriodSeconds:           cfg.BouncerCaptchaGracePeriodSeconds,
		SiteverifyHTTPTimeoutSeconds: cfg.BouncerCaptchaSiteverifyHTTPTimeoutSeconds,
		CustomJsURL:                  cfg.BouncerCaptchaCustomJsURL,
		CustomChallengeURL:           cfg.BouncerCaptchaCustomChallengeURL,
		CustomKey:                    cfg.BouncerCaptchaCustomKey,
		CustomResponse:               cfg.BouncerCaptchaCustomResponse,
		CustomValidateURL:            cfg.BouncerCaptchaCustomValidateURL,
		CustomValidateBody:           cfg.BouncerCaptchaCustomValidateBody,
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

// newOwnerClient constructs the siteverify client, template, and gate for one owner Open.
func newOwnerClient(cfg *configuration.Config, log *slog.Logger, middlewareName, bindKey, _ string) (*Client, error) {
	siteKey, _ := configuration.GetVariable(cfg, "BouncerCaptchaSiteKey")
	secretKey, _ := configuration.GetVariable(cfg, "BouncerCaptchaSecretKey")
	gateSecret, _ := configuration.GetVariable(cfg, "BouncerCaptchaGateSecret")
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
			Timeout:   time.Duration(cfg.BouncerCaptchaSiteverifyHTTPTimeoutSeconds) * time.Second,
		},
		cfg.BouncerCaptchaProvider,
		cfg.BouncerCaptchaCustomJsURL,
		cfg.BouncerCaptchaCustomChallengeURL,
		cfg.BouncerCaptchaCustomKey,
		cfg.BouncerCaptchaCustomResponse,
		cfg.BouncerCaptchaCustomValidateURL,
		cfg.BouncerCaptchaCustomValidateBody,
		siteKey,
		secretKey,
		gateSecret,
		cfg.BouncerCaptchaGateBindIP,
		cfg.BouncerCaptchaFilePath,
		cfg.BouncerCaptchaGracePeriodSeconds,
	)
	if err != nil {
		return nil, err
	}
	client.middlewareName = middlewareName
	client.instanceName = cfg.CaptchaInstanceName
	client.sessionKey = bindKey
	client.incarnation = fmt.Sprintf("%p", client)
	client.log.Info(MsgInstanceStarted, "incarnation", client.incarnation, "reason", "started")
	return client, nil
}
