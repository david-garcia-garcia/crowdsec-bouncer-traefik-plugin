package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/appsec"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/captcha"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/modsecurity"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ratelimit"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

// testLegInstanceName is the instance name every test leg publishes and subscribes to.
// The five reclaim groups are separate, so one string serves all of them.
const testLegInstanceName = "shared"

// testLegFixture configures one published leg on a test middleware config.
type testLegFixture struct {
	leg   string
	empty any // typed nil Watch stores while the alias is clear
	// own enables the leg with testLegInstanceName. variant changes the ownership key.
	own func(config *configuration.Config, variant string)
	// subscribe sets the leg's instance name on a bouncer that does not own it.
	subscribe func(config *configuration.Config)
	// incarnationOf is the incarnation of the leg's Client in a published value, or empty for a typed nil.
	incarnationOf func(published any) string
}

// testBindingTrace is one `crowdsec bouncer bound|unbound` line read back from a JSON log file.
type testBindingTrace struct {
	msg            string
	traefikName    string
	leg            string
	instanceName   string
	incarnation    string
	hasIncarnation bool
}

// testLegFixtures returns the five published legs in plugin.go open and claim order.
// lapiHost is a live LAPI test server; modsecURL is a ModSec sidecar test server.
func testLegFixtures(t *testing.T, lapiHost, modsecURL string) []testLegFixture {
	t.Helper()
	captchaFilePath := writeTestFile(t, "captcha.html", "CAPTCHA_CHALLENGE_PAGE")
	return []testLegFixture{
		{
			leg:   legLAPI,
			empty: (*lapi.Client)(nil),
			own: func(config *configuration.Config, variant string) {
				config.LapiEnabled = true
				config.LapiInstanceName = testLegInstanceName
				config.LapiMode = configuration.LiveMode
				config.LapiHost = lapiHost
				config.LapiPath = "/"
				config.LapiScheme = "http"
				config.LapiKey = "lapi-key-" + variant
			},
			subscribe: func(config *configuration.Config) { config.LapiInstanceName = testLegInstanceName },
			incarnationOf: func(published any) string {
				client, _ := published.(*lapi.Client)
				return client.Incarnation()
			},
		},
		{
			leg:   legAppSec,
			empty: (*appsec.Client)(nil),
			own: func(config *configuration.Config, variant string) {
				config.AppsecEnabled = true
				config.AppsecInstanceName = testLegInstanceName
				config.AppsecScheme = "http"
				config.AppsecHost = "127.0.0.1:1"
				config.AppsecPath = "/"
				config.AppsecKey = "appsec-key-" + variant
			},
			subscribe: func(config *configuration.Config) { config.AppsecInstanceName = testLegInstanceName },
			incarnationOf: func(published any) string {
				client, _ := published.(*appsec.Client)
				return client.Incarnation()
			},
		},
		{
			leg:   legCaptcha,
			empty: (*captcha.Client)(nil),
			own: func(config *configuration.Config, variant string) {
				config.CaptchaEnabled = true
				config.CaptchaInstanceName = testLegInstanceName
				config.CaptchaProvider = configuration.CustomProvider
				config.CaptchaCustomJsURL = "/captcha.js"
				config.CaptchaCustomKey = "dummy-captcha"
				config.CaptchaCustomResponse = "dummy-captcha-response"
				config.CaptchaCustomValidateURL = "http://127.0.0.1/siteverify"
				config.CaptchaSiteKey = "site-" + variant
				config.CaptchaSecretKey = "secret"
				config.CaptchaGateSecret = "gate-secret"
				config.CaptchaFilePath = captchaFilePath
			},
			subscribe: func(config *configuration.Config) { config.CaptchaInstanceName = testLegInstanceName },
			incarnationOf: func(published any) string {
				client, _ := published.(*captcha.Client)
				return client.Incarnation()
			},
		},
		{
			leg:   legModsec,
			empty: (*modsecurity.Client)(nil),
			own: func(config *configuration.Config, variant string) {
				config.ModsecEnabled = true
				config.ModsecInstanceName = testLegInstanceName
				config.ModsecURL = modsecURL + "/" + variant
			},
			subscribe: func(config *configuration.Config) { config.ModsecInstanceName = testLegInstanceName },
			incarnationOf: func(published any) string {
				client, _ := published.(*modsecurity.Client)
				return client.Incarnation()
			},
		},
		{
			leg:   legRateLimit,
			empty: (*ratelimit.Client)(nil),
			own: func(config *configuration.Config, variant string) {
				enableTestRateLimit(config, testRateLimitDeadRedis)
				config.RateLimitInstanceName = testLegInstanceName
				config.RateLimitBuckets[0].Name = "per-ip-" + variant
			},
			subscribe: func(config *configuration.Config) { config.RateLimitInstanceName = testLegInstanceName },
			incarnationOf: func(published any) string {
				client, _ := published.(*ratelimit.Client)
				return client.Incarnation()
			},
		},
	}
}

// testLegServers starts the live LAPI and ModSec sidecar the fixtures point at.
func testLegServers(t *testing.T) (lapiHost, modsecURL string) {
	t.Helper()
	var hits int64
	lapiServer := liveLAPI(t, nil, &hits)
	// Closure: Yaegi v0.16 types httptest.Server.Close as a method value with a receiver.
	t.Cleanup(func() { lapiServer.Close() })
	parsed, err := url.Parse(lapiServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Host, modsecSidecar(t).URL
}

// cfgNoLegs is a middleware config that owns nothing and does not bounce.
// traced logs JSON at TRACE; otherwise it logs at ERROR.
func cfgNoLegs(traced bool) *configuration.Config {
	config := getTestConfig()
	config.BouncerEnabled = false
	config.LapiEnabled = false
	config.LapiKey = ""
	config.BouncerForwardedHeadersTrustedIPs = []string{"127.0.0.1/32"}
	config.BouncerForwardedHeadersCustomName = "X-Forwarded-For"
	config.LogLevel = "ERROR"
	if traced {
		config.LogLevel = "TRACE"
		config.LogFormat = "json"
	}
	return config
}

// newTestOwner runs New for a middleware that owns only fixture's leg, or nothing when variant is empty.
func newTestOwner(t *testing.T, fixture testLegFixture, traefikName, variant string) {
	t.Helper()
	config := cfgNoLegs(false)
	if variant != "" {
		fixture.own(config, variant)
	}
	if _, err := New(context.Background(), testNextOK(), config, traefikName); err != nil {
		t.Fatalf("%s owner %s variant %q: %v", fixture.leg, traefikName, variant, err)
	}
}

// readBindingTraces returns the bound / unbound lines logPath holds, in order.
func readBindingTraces(t *testing.T, logPath string) []testBindingTrace {
	t.Helper()
	content, err := os.ReadFile(logPath) // #nosec G304 -- test-created temp file
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	traces := make([]testBindingTrace, 0, len(lines))
	for _, line := range lines {
		// fmt.Sprint and nil checks, not comma-ok assertions: Yaegi keeps the previous loop
		// iteration's value when a comma-ok assertion fails.
		entry := readLogEntry(t, line)
		msg := fmt.Sprint(entry["msg"])
		if msg != "crowdsec bouncer bound" && msg != "crowdsec bouncer unbound" {
			continue
		}
		trace := testBindingTrace{
			msg:          msg,
			traefikName:  fmt.Sprint(entry["traefikName"]),
			leg:          fmt.Sprint(entry["leg"]),
			instanceName: fmt.Sprint(entry["instanceName"]),
		}
		if entry["incarnation"] != nil {
			trace.incarnation = fmt.Sprint(entry["incarnation"])
			trace.hasIncarnation = true
		}
		traces = append(traces, trace)
	}
	return traces
}

// isFor reports whether trace is msg for traefikName on leg's testLegInstanceName.
func (trace testBindingTrace) isFor(msg, traefikName, leg string) bool {
	return trace.msg == msg && trace.traefikName == traefikName && trace.leg == leg && trace.instanceName == testLegInstanceName
}

// readLogEntries returns every JSON line logPath holds whose msg is msg.
func readLogEntries(t *testing.T, logPath, msg string) []map[string]interface{} {
	t.Helper()
	content, err := os.ReadFile(logPath) // #nosec G304 -- test-created temp file
	if err != nil {
		t.Fatal(err)
	}
	var matched []map[string]interface{}
	for _, line := range strings.Split(strings.TrimSpace(string(content)), "\n") {
		entry := readLogEntry(t, line)
		if entry["msg"] == msg {
			matched = append(matched, entry)
		}
	}
	return matched
}

// readLogEntry decodes one JSON log line. A blank line is an empty entry.
func readLogEntry(t *testing.T, line string) map[string]interface{} {
	t.Helper()
	entry := map[string]interface{}{}
	if strings.TrimSpace(line) == "" {
		return entry
	}
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		t.Fatalf("log line is not JSON: %s: %v", line, err)
	}
	return entry
}

// publishedIncarnation is the incarnation the reclaim alias of fixture's leg currently publishes,
// or empty when the alias is clear.
func publishedIncarnation(fixture testLegFixture) string {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	incarnation := ""
	reclaim.Watch(ctx, instanceAlias(fixture.leg, testLegInstanceName), fixture.empty, func(published any) {
		notice, _ := published.(reclaim.Published)
		incarnation = fixture.incarnationOf(notice.Value)
	})
	return incarnation
}

// assertBeforePublishTraces checks what a subscriber traced before any owner published. Under Yaegi
// (Traefik) Watch delivers the typed nil and the subscriber traces one unbound line without
// incarnation; compiled Go skips that delivery, so nothing is traced.
func assertBeforePublishTraces(t *testing.T, traces []testBindingTrace, subscriberName, leg string) {
	t.Helper()
	if len(traces) > 1 {
		t.Fatalf("subscribe before publish traced %+v, want at most one line", traces)
	}
	for _, trace := range traces {
		if !trace.isFor("crowdsec bouncer unbound", subscriberName, leg) || trace.hasIncarnation {
			t.Fatalf("subscribe before publish traced %+v, want unbound for %s/%s without incarnation", trace, subscriberName, leg)
		}
	}
}

// assertReplaceTraces checks publish A, replace by B, and clear: bound A, unbound A, bound B, unbound B.
// It returns the incarnation bound last.
func assertReplaceTraces(t *testing.T, traces []testBindingTrace, subscriberName, leg string) string {
	t.Helper()
	wantMsgs := []string{"crowdsec bouncer bound", "crowdsec bouncer unbound", "crowdsec bouncer bound", "crowdsec bouncer unbound"}
	if len(traces) != len(wantMsgs) {
		t.Fatalf("traces %+v, want %v", traces, wantMsgs)
	}
	for i, trace := range traces {
		if !trace.isFor(wantMsgs[i], subscriberName, leg) || !trace.hasIncarnation || trace.incarnation == "" {
			t.Fatalf("trace %d = %+v, want %q for %s/%s with an incarnation", i, trace, wantMsgs[i], subscriberName, leg)
		}
	}
	incarnationA, incarnationB := traces[0].incarnation, traces[2].incarnation
	if incarnationA == incarnationB {
		t.Fatalf("replace kept incarnation %s", incarnationA)
	}
	if traces[1].incarnation != incarnationA || traces[3].incarnation != incarnationB {
		t.Fatalf("unbound lines %s, %s want %s, %s", traces[1].incarnation, traces[3].incarnation, incarnationA, incarnationB)
	}
	return incarnationB
}

// TestNew_LegBindingTraces pins, for each published leg, the bound / unbound TRACE lines a
// subscriber logs across subscribe-before-publish, publish, replace, and clear.
func TestNew_LegBindingTraces(t *testing.T) {
	lapiHost, modsecURL := testLegServers(t)
	for _, fixture := range testLegFixtures(t, lapiHost, modsecURL) {
		t.Run(fixture.leg, func(t *testing.T) {
			logPath := newTestLogFile(t)
			subscriberName := fixture.leg + "-subscriber"
			ownerName := fixture.leg + "-owner"

			// Subscribe before any owner publishes.
			subscriberConfig := cfgNoLegs(true)
			subscriberConfig.BouncerEnabled = true
			fixture.subscribe(subscriberConfig)
			if _, err := New(context.Background(), testNextOK(), subscriberConfig, subscriberName); err != nil {
				t.Fatal(err)
			}
			beforePublish := readBindingTraces(t, logPath)
			assertBeforePublishTraces(t, beforePublish, subscriberName, fixture.leg)

			// Publish A, replace A by B (new ownership key, same alias), then drop the leg.
			newTestOwner(t, fixture, ownerName, "a")
			newTestOwner(t, fixture, ownerName, "b")
			publishedB := publishedIncarnation(fixture)
			newTestOwner(t, fixture, ownerName, "")

			boundB := assertReplaceTraces(t, readBindingTraces(t, logPath)[len(beforePublish):], subscriberName, fixture.leg)
			if boundB != publishedB {
				t.Fatalf("bound incarnation %s, alias published %s", boundB, publishedB)
			}
			if cleared := publishedIncarnation(fixture); cleared != "" {
				t.Fatalf("dropping the leg must clear its alias, still publishes %s", cleared)
			}
		})
	}
}

// assertRollbackAliases checks that the legs before takenIndex are clear and the taken and later
// legs are still published (the taken one by its other owner, later ones from the earlier New).
func assertRollbackAliases(t *testing.T, fixtures []testLegFixture, takenIndex int) {
	t.Helper()
	for i, fixture := range fixtures {
		published := publishedIncarnation(fixture) != ""
		if i < takenIndex && published {
			t.Fatalf("earlier leg %s must be cleared by the rollback", fixture.leg)
		}
		if i >= takenIndex && !published {
			t.Fatalf("leg %s must stay published (taken by another owner, or later than the taken leg)", fixture.leg)
		}
	}
}

// assertOneNameTakenError checks that logPath holds exactly one ERROR naming leg and the rejected publisher.
func assertOneNameTakenError(t *testing.T, logPath, leg, rejected string) {
	t.Helper()
	takenLines := readLogEntries(t, logPath, "crowdsec instance name taken")
	if len(takenLines) != 1 {
		t.Fatalf("instance name taken lines %v, want one", takenLines)
	}
	if takenLines[0]["level"] != "ERROR" || takenLines[0]["leg"] != leg ||
		takenLines[0]["instanceName"] != testLegInstanceName || takenLines[0]["rejected"] != rejected {
		t.Fatalf("instance name taken line %v", takenLines[0])
	}
}

// TestNew_ClaimRollbackClearsEarlierLegs pins the claim rollback: a taken instance name on one leg
// clears exactly the aliases this New already claimed on earlier legs, leaves later legs as they
// were, and logs one ERROR naming the taken leg.
func TestNew_ClaimRollbackClearsEarlierLegs(t *testing.T) {
	lapiHost, modsecURL := testLegServers(t)
	fixtures := testLegFixtures(t, lapiHost, modsecURL)
	for takenIndex := 1; takenIndex < len(fixtures); takenIndex++ {
		taken := fixtures[takenIndex]
		t.Run(taken.leg, func(t *testing.T) {
			logPath := newTestLogFile(t)
			const mixedName = "mixed-owner"

			// mixed-owner first publishes every leg but the taken one; another owner then takes that name.
			published := cfgNoLegs(false)
			for i, fixture := range fixtures {
				if i != takenIndex {
					fixture.own(published, "a")
				}
			}
			if _, err := New(context.Background(), testNextOK(), published, mixedName); err != nil {
				t.Fatal(err)
			}
			newTestOwner(t, taken, "taker", "a")

			// The same middleware now also owns the taken leg: the claim fails and rolls back.
			mixed := cfgNoLegs(true)
			for _, fixture := range fixtures {
				fixture.own(mixed, "a")
			}
			if _, err := New(context.Background(), testNextOK(), mixed, mixedName); err == nil {
				t.Fatalf("claiming taken %s name must fail New", taken.leg)
			}

			assertRollbackAliases(t, fixtures, takenIndex)
			assertOneNameTakenError(t, logPath, taken.leg, mixedName)
		})
	}
}
