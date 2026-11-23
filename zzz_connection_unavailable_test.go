package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/bouncer"
)

// countConnectionLines is how many lines of logFilePath carry msg at level for router traefikName, leg, and
// instance instanceName.
func countConnectionLines(t *testing.T, logFilePath, msg, level, traefikName, leg, instanceName string) int {
	t.Helper()
	total := 0
	for _, entry := range readLogEntries(t, logFilePath, msg) {
		// fmt.Sprint, not comma-ok assertions: yaegi runs this file.
		if fmt.Sprint(entry["level"]) == level && fmt.Sprint(entry["traefikName"]) == traefikName &&
			fmt.Sprint(entry["leg"]) == leg && fmt.Sprint(entry["instanceName"]) == instanceName {
			total++
		}
	}
	return total
}

// TestNew_UnpublishedConnectionWarnsOnce proves, through New and the real Watch, that a router naming a LAPI
// instance no middleware publishes (a typo) logs WARN "crowdsec bouncer connection unavailable" exactly once
// while every request gets the LAPI failure action. Compiled Go's Watch delivers nothing for that name and Yaegi's
// delivers the typed nil; both log one WARN, never two. A reload that rebuilds the router adds no WARN, and no INFO
// follows while the name stays unpublished.
func TestNew_UnpublishedConnectionWarnsOnce(t *testing.T) {
	bouncer.ResetConnectionWarningsForTest()
	t.Cleanup(bouncer.ResetConnectionWarningsForTest)
	logFilePath := newTestLogFile(t)
	const warnMsg = "crowdsec bouncer connection unavailable"
	const infoMsg = "crowdsec bouncer connection available"

	cfg := getTestConfig()
	cfg.LapiEnabled = false
	cfg.LapiKey = ""
	cfg.LapiInstanceName = "shraed"
	cfg.LogLevel = "INFO"
	cfg.LogFormat = "json"
	cfg.LogFilePath = logFilePath
	handler, err := New(context.Background(), testNextOK(), cfg, "app-a")
	if err != nil {
		t.Fatal(err)
	}
	if got := countConnectionLines(t, logFilePath, warnMsg, "WARN", "app-a", "lapi", "shraed"); got != 1 {
		t.Fatalf("router on an unpublished LAPI name: WARN lines=%d want 1", got)
	}
	if status := serveTestRequests(handler, "203.0.113.80", 3); status != http.StatusForbidden {
		t.Fatalf("unpublished LAPI name: status %d, want the LAPI failure action's 403", status)
	}

	// A reload rebuilds app-a while the name is still unpublished: the same outage, no second WARN.
	if _, err := New(context.Background(), testNextOK(), cfg, "app-a"); err != nil {
		t.Fatal(err)
	}
	if got := countConnectionLines(t, logFilePath, warnMsg, "WARN", "app-a", "lapi", "shraed"); got != 1 {
		t.Fatalf("app-a rebuilt: WARN lines=%d want 1", got)
	}
	if got := countConnectionLines(t, logFilePath, infoMsg, "INFO", "app-a", "lapi", "shraed"); got != 0 {
		t.Fatalf("no owner ever published: INFO lines=%d want 0", got)
	}
}
