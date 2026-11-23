package bouncer

import (
	"log/slog"
	"sync"
)

const (
	// msgConnectionUnavailable is the WARN line when a LAPI, AppSec, ModSec, or captcha leg this route subscribes
	// to has no published connection: every request now gets that leg's failure action.
	msgConnectionUnavailable = "crowdsec bouncer connection unavailable"
	// msgConnectionAvailable is the INFO line when a connection binds while this router name and leg have a
	// msgConnectionUnavailable pending (connectionWarnings).
	msgConnectionAvailable = "crowdsec bouncer connection available"
)

// connectionWarnings is the process-wide record of connection-unavailable WARN lines no INFO has answered yet,
// keyed by the subscriber's Traefik middleware name and leg, with the instance name each WARN named.
// It outlives one Bouncer: a reload rebuilds a subscriber as a new Bouncer with the same name, and that new
// Bouncer must answer (or not repeat) the WARN its previous instance logged. An entry exists only while its
// WARN is pending; a middleware removed while warned leaves its entries until a router of that name binds
// or is rebuilt without those legs. The rate-limit leg logs its own documented lines (connectionLine).
type connectionWarnings struct {
	mu      sync.Mutex
	pending map[string]string // connectionWarningKey(traefikName, leg) → instanceName of the pending WARN
}

//nolint:gochecknoglobals // process-wide so a WARN outlives the Bouncer a Traefik reload replaces
var pendingConnectionWarnings = &connectionWarnings{pending: map[string]string{}}

// connectionWarningKey is the pending key of one router name and leg. A string, not a struct: Yaegi runs this.
func connectionWarningKey(traefikName, leg string) string {
	return leg + "\x00" + traefikName
}

// connectionLine is the message and attrs of the unavailable (WARN) or available (INFO) line of leg. The
// rate-limit leg keeps its own lines, without a leg attr.
func connectionLine(leg, instanceName string, available bool) (string, []any) {
	if leg == legRateLimit {
		if available {
			return msgRateLimitOwnerAvailable, []any{"instanceName", instanceName}
		}
		return msgRateLimitOwnerUnavailable, []any{"instanceName", instanceName}
	}
	attrs := []any{"leg", leg, "instanceName", instanceName}
	if available {
		return msgConnectionAvailable, attrs
	}
	return msgConnectionUnavailable, attrs
}

// warnUnavailable logs the WARN line of leg and records it as pending, unless traefikName already has a pending
// WARN on leg for the same instanceName (the same outage, seen again by a rebuilt Bouncer). A pending WARN for
// another instance name is replaced: the router now misses a different connection. It logs under the lock so
// the order of the lines matches the order of the record.
func (warnings *connectionWarnings) warnUnavailable(log *slog.Logger, traefikName, leg, instanceName string) {
	warnings.mu.Lock()
	defer warnings.mu.Unlock()
	key := connectionWarningKey(traefikName, leg)
	if warned, ok := warnings.pending[key]; ok && warned == instanceName {
		return
	}
	warnings.pending[key] = instanceName
	msg, attrs := connectionLine(leg, instanceName, false)
	log.Warn(msg, attrs...)
}

// answerAvailable logs the INFO line of leg and drops the pending WARN of traefikName on leg, when there is
// one. A router of that name has the leg again, whichever instance name the WARN named. No pending WARN logs
// nothing.
func (warnings *connectionWarnings) answerAvailable(log *slog.Logger, traefikName, leg, instanceName, incarnation string) {
	warnings.mu.Lock()
	defer warnings.mu.Unlock()
	key := connectionWarningKey(traefikName, leg)
	if _, ok := warnings.pending[key]; !ok {
		return
	}
	delete(warnings.pending, key)
	msg, attrs := connectionLine(leg, instanceName, true)
	log.Info(msg, append(attrs, "incarnation", incarnation)...)
}

// forget drops the pending WARN of traefikName on leg without a line: a router of that name no longer
// subscribes to the leg, so no connection will answer it.
func (warnings *connectionWarnings) forget(traefikName, leg string) {
	warnings.mu.Lock()
	defer warnings.mu.Unlock()
	delete(warnings.pending, connectionWarningKey(traefikName, leg))
}

// ResetConnectionWarningsForTest drops every pending connection-unavailable WARN of the process. Test-only.
func ResetConnectionWarningsForTest() {
	pendingConnectionWarnings.mu.Lock()
	defer pendingConnectionWarnings.mu.Unlock()
	pendingConnectionWarnings.pending = map[string]string{}
}
