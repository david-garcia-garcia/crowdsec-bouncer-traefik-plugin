package bouncer

import (
	"log/slog"
	"sync"
)

// rateLimitOwnerWarnings is the process-wide record of owner-unavailable WARN lines no INFO has answered yet,
// keyed by the subscriber's Traefik middleware name, with the rate-limit instance name each WARN named.
// It outlives one Bouncer: a reload rebuilds a subscriber as a new Bouncer with the same name, and that new
// Bouncer must answer (or not repeat) the WARN its previous instance logged. An entry exists only while its
// WARN is pending; a middleware removed while warned leaves its one entry until a router of that name binds
// or is rebuilt without the rate limit.
type rateLimitOwnerWarnings struct {
	mu      sync.Mutex
	pending map[string]string // traefikName → instanceName of the pending WARN
}

//nolint:gochecknoglobals // process-wide so a WARN outlives the Bouncer a Traefik reload replaces
var pendingRateLimitOwnerWarnings = &rateLimitOwnerWarnings{pending: map[string]string{}}

// warnUnavailable logs WARN msgRateLimitOwnerUnavailable and records it as pending, unless traefikName already
// has a pending WARN for the same instanceName (the same outage, seen again by a rebuilt Bouncer). A pending WARN
// for another instance name is replaced: the router now misses a different owner. It logs under the lock so the
// order of the lines matches the order of the record.
func (warnings *rateLimitOwnerWarnings) warnUnavailable(log *slog.Logger, traefikName, instanceName string) {
	warnings.mu.Lock()
	defer warnings.mu.Unlock()
	if warned, ok := warnings.pending[traefikName]; ok && warned == instanceName {
		return
	}
	warnings.pending[traefikName] = instanceName
	log.Warn(msgRateLimitOwnerUnavailable, "instanceName", instanceName)
}

// answerAvailable logs INFO msgRateLimitOwnerAvailable and drops the pending WARN of traefikName, when there is
// one. A router of that name charges again, whichever instance name the WARN named. No pending WARN logs nothing.
func (warnings *rateLimitOwnerWarnings) answerAvailable(log *slog.Logger, traefikName, instanceName, incarnation string) {
	warnings.mu.Lock()
	defer warnings.mu.Unlock()
	if _, ok := warnings.pending[traefikName]; !ok {
		return
	}
	delete(warnings.pending, traefikName)
	log.Info(msgRateLimitOwnerAvailable, "instanceName", instanceName, "incarnation", incarnation)
}

// forget drops the pending WARN of traefikName without a line: a router of that name no longer subscribes to
// the rate limit, so no owner will answer it.
func (warnings *rateLimitOwnerWarnings) forget(traefikName string) {
	warnings.mu.Lock()
	defer warnings.mu.Unlock()
	delete(warnings.pending, traefikName)
}

// ResetRateLimitOwnerWarningsForTest drops every pending owner-unavailable WARN of the process. Test-only.
func ResetRateLimitOwnerWarningsForTest() {
	pendingRateLimitOwnerWarnings.mu.Lock()
	defer pendingRateLimitOwnerWarnings.mu.Unlock()
	pendingRateLimitOwnerWarnings.pending = map[string]string{}
}
