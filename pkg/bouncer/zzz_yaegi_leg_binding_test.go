package bouncer

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/yaegitest"
)

// TestYaegi_LegBindingReceiveAndLoad runs the leg bindings under Yaegi v0.16.1, the way Traefik
// loads them: New with Subscriptions, then each Receive<Leg> with an empty, a published, the same,
// a replaced, and an empty value. The program checks the bound / unbound trace sequence of every
// leg, the LAPI client the route loads after each step, and the rate-limit owner WARN / INFO counts.
func TestYaegi_LegBindingReceiveAndLoad(t *testing.T) {
	dir := t.TempDir()
	templatePath := filepath.Join(dir, "captcha.html")
	if err := os.WriteFile(templatePath, []byte("captcha"), 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "trace.log")
	yaegitest.Run(t, yaegitest.GoPath(t), fmt.Sprintf(yaegiLegBindingProgram, templatePath, logPath))
}

// yaegiLegBindingProgram is the package main program TestYaegi_LegBindingReceiveAndLoad interprets.
// The two %q verbs are the captcha template path and the TRACE log file path; %% escapes the program's own verbs.
const yaegiLegBindingProgram = `package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/appsec"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/bouncer"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/captcha"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/modsecurity"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ratelimit"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

const templatePath = %q
const logPath = %q

// legCase is one leg: its route callback, its typed nil, and two published Clients.
type legCase struct {
	leg          string
	receive      func(any)
	empty        any
	first        any
	second       any
	firstIncarnation  string
	secondIncarnation string
}

func exitWithFailure(message string) {
	println(message)
	os.Exit(1)
}

func ownerConfig(variant string) *configuration.Config {
	config := configuration.New()
	config.LapiEnabled = true
	config.LapiMode = configuration.LiveMode
	config.LapiScheme = "http"
	config.LapiHost = "127.0.0.1:1"
	config.LapiKey = "lapi-key-" + variant
	config.LapiMetricsUpdateIntervalSeconds = 0
	config.AppsecEnabled = true
	config.AppsecScheme = "http"
	config.AppsecHost = "127.0.0.1:1"
	config.AppsecPath = "/"
	config.AppsecKey = "appsec-key-" + variant
	config.CaptchaEnabled = true
	config.CaptchaProvider = configuration.CustomProvider
	config.CaptchaCustomJsURL = "/captcha.js"
	config.CaptchaCustomKey = "dummy-captcha"
	config.CaptchaCustomResponse = "dummy-captcha-response"
	config.CaptchaCustomValidateURL = "http://127.0.0.1:1/siteverify"
	config.CaptchaSiteKey = "site-" + variant
	config.CaptchaSecretKey = "secret"
	config.CaptchaGateSecret = "gate-secret"
	config.CaptchaFilePath = templatePath
	config.ModsecEnabled = true
	config.ModsecURL = "http://127.0.0.1:1/" + variant
	return config
}

// openedOwner is one owner's five Clients, opened under Yaegi.
type openedOwner struct {
	lapi      *lapi.Client
	appsec    *appsec.Client
	captcha   *captcha.Client
	modsec    *modsecurity.Client
	rateLimit *ratelimit.Client
}

func openOwner(variant string) openedOwner {
	ctx := context.Background()
	config := ownerConfig(variant)
	quiet := logger.New("ERROR", "")
	lapiClient, err := lapi.Open(ctx, config, quiet, "yaegi-owner", "test")
	if err != nil {
		exitWithFailure("lapi.Open: " + err.Error())
	}
	appsecClient, err := appsec.Open(ctx, config, quiet, "yaegi-owner", "test")
	if err != nil {
		exitWithFailure("appsec.Open: " + err.Error())
	}
	captchaClient, err := captcha.Open(ctx, config, quiet, "yaegi-owner", "test")
	if err != nil {
		exitWithFailure("captcha.Open: " + err.Error())
	}
	modsecClient, err := modsecurity.Open(ctx, config, quiet, "yaegi-owner", "test")
	if err != nil {
		exitWithFailure("modsecurity.Open: " + err.Error())
	}
	rateLimitClient, err := ratelimit.Open(ctx, "yaegi-owner", ratelimit.Settings{
		Buckets:      []ratelimit.BucketRule{{Name: "per-ip-" + variant, Requests: 5, Window: "1m", Key: []ratelimit.KeyPart{{From: ratelimit.KeyFromIP}}}},
		InstanceName: "shared",
		Policy:       ratelimit.Policy{FailureAction: "passthrough", ResponseHeaders: true, StatusCode: 429},
		Redis:        ratelimit.RedisSettings{Host: "127.0.0.1:1"},
	}, quiet)
	if err != nil {
		exitWithFailure("ratelimit.Open: " + err.Error())
	}
	return openedOwner{lapi: lapiClient, appsec: appsecClient, captcha: captchaClient, modsec: modsecClient, rateLimit: rateLimitClient}
}

func main() {
	first := openOwner("a")
	second := openOwner("b")

	routeConfig := configuration.New()
	routeConfig.LapiInstanceName = "shared"
	routeConfig.AppsecInstanceName = "shared"
	routeConfig.CaptchaInstanceName = "shared"
	routeConfig.ModsecInstanceName = "shared"
	routeConfig.RateLimitInstanceName = "shared"
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	subscriptions := bouncer.Subscriptions{LAPI: true, AppSec: true, Captcha: true, ModSec: true, RateLimit: true}
	route, err := bouncer.New(next, "yaegi-route", routeConfig, subscriptions, logger.NewWithFormat("TRACE", logPath, "json"))
	if err != nil {
		exitWithFailure("bouncer.New: " + err.Error())
	}

	legs := []legCase{
		{
			leg: "lapi", receive: route.ReceiveLAPI, empty: (*lapi.Client)(nil), first: first.lapi, second: second.lapi,
			firstIncarnation: first.lapi.Incarnation(), secondIncarnation: second.lapi.Incarnation(),
		},
		{
			leg: "appsec", receive: route.ReceiveAppSec, empty: (*appsec.Client)(nil), first: first.appsec, second: second.appsec,
			firstIncarnation: first.appsec.Incarnation(), secondIncarnation: second.appsec.Incarnation(),
		},
		{
			leg: "captcha", receive: route.ReceiveCaptcha, empty: (*captcha.Client)(nil), first: first.captcha, second: second.captcha,
			firstIncarnation: first.captcha.Incarnation(), secondIncarnation: second.captcha.Incarnation(),
		},
		{
			leg: "modsec", receive: route.ReceiveModSec, empty: (*modsecurity.Client)(nil), first: first.modsec, second: second.modsec,
			firstIncarnation: first.modsec.Incarnation(), secondIncarnation: second.modsec.Incarnation(),
		},
		{
			leg: "ratelimit", receive: route.ReceiveRateLimit, empty: (*ratelimit.Client)(nil), first: first.rateLimit, second: second.rateLimit,
			firstIncarnation: first.rateLimit.Incarnation(), secondIncarnation: second.rateLimit.Incarnation(),
		},
	}
	for _, leg := range legs {
		if leg.firstIncarnation == "" || leg.firstIncarnation == leg.secondIncarnation {
			exitWithFailure(leg.leg + ": Open must return two Clients with distinct incarnations")
		}
	}

	// Each leg: empty, publish, same again (no-op), replace, clear.
	for _, leg := range legs {
		leg.receive(reclaim.Published{Value: leg.empty})
		leg.receive(reclaim.Published{Value: leg.first})
		leg.receive(reclaim.Published{Value: leg.first})
		if leg.leg == "lapi" && route.LapiClient() != first.lapi {
			exitWithFailure("lapi: route must load the first published client")
		}
		leg.receive(reclaim.Published{Value: leg.second})
		if leg.leg == "lapi" && route.LapiClient() != second.lapi {
			exitWithFailure("lapi: route must load the replacing client")
		}
		leg.receive(reclaim.Published{Value: leg.empty})
		if leg.leg == "lapi" && route.LapiClient() != nil {
			exitWithFailure("lapi: route must load nil after the alias clears")
		}
	}

	content, err := os.ReadFile(logPath)
	if err != nil {
		exitWithFailure("read log: " + err.Error())
	}
	var traced []string
	ownerWarnings, ownerRecoveries := 0, 0
	for _, line := range strings.Split(strings.TrimSpace(string(content)), "\n") {
		entry := map[string]interface{}{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			exitWithFailure("log line is not JSON: " + line)
		}
		msg := fmt.Sprint(entry["msg"])
		if msg == "crowdsec bouncer rate limit owner unavailable" && fmt.Sprint(entry["level"]) == "WARN" {
			ownerWarnings++
		}
		if msg == "crowdsec bouncer rate limit owner available" && fmt.Sprint(entry["level"]) == "INFO" {
			ownerRecoveries++
		}
		if msg != "crowdsec bouncer bound" && msg != "crowdsec bouncer unbound" {
			continue
		}
		// fmt.Sprint, not a comma-ok assertion: Yaegi keeps the previous iteration's value when one fails.
		incarnation := ""
		if entry["incarnation"] != nil {
			incarnation = fmt.Sprint(entry["incarnation"])
		}
		traced = append(traced, msg+" "+fmt.Sprint(entry["leg"])+" "+fmt.Sprint(entry["instanceName"])+" "+incarnation)
	}
	var want []string
	for _, leg := range legs {
		want = append(want,
			"crowdsec bouncer unbound "+leg.leg+" shared ",
			"crowdsec bouncer bound "+leg.leg+" shared "+leg.firstIncarnation,
			"crowdsec bouncer unbound "+leg.leg+" shared "+leg.firstIncarnation,
			"crowdsec bouncer bound "+leg.leg+" shared "+leg.secondIncarnation,
			"crowdsec bouncer unbound "+leg.leg+" shared "+leg.secondIncarnation,
		)
	}
	if strings.Join(traced, "\n") != strings.Join(want, "\n") {
		exitWithFailure("traces:\n" + strings.Join(traced, "\n") + "\nwant:\n" + strings.Join(want, "\n"))
	}
	// The rate-limit leg warns on each move to no Client (the first empty and the final clear) and logs
	// INFO on the bind that ends the first warning; publishing the same Client and a replace log neither.
	if ownerWarnings != 2 || ownerRecoveries != 1 {
		exitWithFailure(fmt.Sprintf("rate limit owner lines: %%d WARN %%d INFO, want 2 and 1", ownerWarnings, ownerRecoveries))
	}
}
`
