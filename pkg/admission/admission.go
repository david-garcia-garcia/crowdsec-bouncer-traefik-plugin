// Package admission wraps the utilities backoff Gate for one backend leg (LAPI, AppSec or ModSec).
// It logs once when the leg enters backoff and once when a probe shows it healthy again, never per
// request. When the utilities gate drops an idle leg, the wrapper clears its backoff state without a
// log line, so the next trip logs entering backoff again.
package admission

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/david-garcia-garcia/traefik-middleware-utilities/backendbackoff"
)

// TripFailures is the failure budget: each failure spends one unit and each success earns back
// FailureRatio/(1-FailureRatio). With both values the gate trips after 5 failures in a row, or when
// failures stay above about 30% of requests. Fixed on purpose: only the cooldown is an operator knob.
const (
	TripFailures = 5
	FailureRatio = 0.30
)

// Config is the cooldown for one leg plus its two transition log lines.
type Config struct {
	// Leg names the backend in errors and is the gate key ("lapi", "appsec", "modsec").
	Leg string
	// PeriodSecs is the cooldown after a trip. 0 or less builds no gate.
	PeriodSecs int64
	// MsgStarted is the WARN line logged when the leg enters backoff.
	MsgStarted string
	// MsgEnded is the INFO line logged when the leg is healthy again.
	MsgEnded string
}

// Gate is one leg's admission gate. A nil *Gate admits every request.
type Gate struct {
	inner      *backendbackoff.Gate
	key        string
	log        *slog.Logger
	msgStarted string
	msgEnded   string

	// mu also serializes the calls into inner, so backingOff changes in the order inner saw them.
	mu         sync.Mutex
	backingOff bool
}

// Ticket is one Admit outcome. Pass it to Report once after a real backend attempt.
type Ticket struct {
	// Admitted means the caller may call the backend.
	Admitted bool
	// permit is the utilities generation for this admission. Report counts only when it still matches.
	permit backendbackoff.Permit
}

// New builds a Gate when cfg.PeriodSecs is greater than zero, else returns nil.
// The cooldown is fixed (no exponential growth). Jitter and TTL stay unset so a partial utilities
// Config disables jitter and keeps the utilities idle TTL.
func New(cfg Config, log *slog.Logger) (*Gate, error) {
	if cfg.PeriodSecs <= 0 {
		return nil, nil //nolint:nilnil // omitted backoff means no gate
	}
	cooldown := time.Duration(cfg.PeriodSecs) * time.Second
	inner, err := backendbackoff.New(backendbackoff.Config{
		TripFailures: TripFailures,
		FailureRatio: FailureRatio,
		BaseCooldown: cooldown,
		MaxCooldown:  cooldown,
	})
	if err != nil {
		return nil, fmt.Errorf("%s admission gate: %w", cfg.Leg, err)
	}
	return &Gate{
		inner:      inner,
		key:        cfg.Leg,
		log:        log,
		msgStarted: cfg.MsgStarted,
		msgEnded:   cfg.MsgEnded,
	}, nil
}

// Admit asks the gate whether this request may call the backend.
// The first denied admission logs MsgStarted. Later denials stay silent until a probe succeeds or
// the utilities gate drops the idle leg.
func (g *Gate) Admit(ctx context.Context) (Ticket, error) {
	if g == nil {
		return Ticket{Admitted: true}, nil
	}
	// Allow returns a Permit and takes no context; keep the early exit on a finished request.
	if err := ctx.Err(); err != nil {
		return Ticket{}, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	permit, wait, err := g.inner.Allow(g.key)
	if err != nil {
		return Ticket{}, err
	}
	if !permit.Allowed() {
		if !g.backingOff {
			g.backingOff = true
			g.log.Warn(g.msgStarted, "retryIn", wait.String(), "reason", "unhealthy")
		}
		return Ticket{}, nil
	}
	if !permit.Probe() {
		// The leg is closed. If it was backing off, the utilities gate dropped it idle: no probe
		// showed the backend healthy, so nothing is logged.
		g.backingOff = false
	}
	return Ticket{Admitted: true, permit: permit}, nil
}

// Report records a real backend attempt. MsgEnded is logged only when a probe's report is applied.
// A nil gate, an unadmitted ticket, or a stale permit does not log that line.
func (g *Gate) Report(ticket Ticket, success bool) error {
	if g == nil || !ticket.Admitted {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	applied, err := g.inner.Report(ticket.permit, success)
	if err != nil {
		return err
	}
	if !success || !ticket.permit.Probe() || !applied {
		return nil
	}
	if g.backingOff {
		g.backingOff = false
		g.log.Info(g.msgEnded, "reason", "healthy")
	}
	return nil
}

// Record is Report for the request path: a failed Report is logged at ERROR, not returned.
func (g *Gate) Record(ticket Ticket, success bool) {
	if err := g.Report(ticket, success); err != nil {
		g.log.Error("fail to report "+g.key+" admission outcome", "error", err, "success", success)
	}
}

// BackingOff reports whether the leg is backing off: MsgStarted was logged, no probe has succeeded
// since, and the utilities gate still holds the leg tripped.
func (g *Gate) BackingOff() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.backingOff {
		// A leg the utilities gate dropped idle is not tripped; clear it as Admit would, silently.
		if tripped, err := g.inner.Tripped(g.key); err == nil && !tripped {
			g.backingOff = false
		}
	}
	return g.backingOff
}

// Close releases the utilities gate. Later Admit and Report return an error.
func (g *Gate) Close() {
	if g == nil {
		return
	}
	g.inner.Close()
}

// Inner is the utilities gate for tests that freeze the clock.
func (g *Gate) Inner() *backendbackoff.Gate {
	if g == nil {
		return nil
	}
	return g.inner
}
