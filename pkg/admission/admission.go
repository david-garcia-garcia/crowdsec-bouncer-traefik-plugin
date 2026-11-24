// Package admission wraps the utilities backoff Gate for one backend leg (LAPI, AppSec or ModSec).
// It logs once when the leg enters backoff and once when a probe shows it healthy again, never per
// request. The utilities gate forgets a leg that sees no request for 60 seconds; the wrapper then
// clears its backoff state without a log line, so the next trip logs entering backoff again.
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

// idleTTL is how long the utilities gate keeps a leg that sees no admission. Every Admit, admitted
// or not, and every Report the gate applies restart it. Once it elapses, the next Admit starts from a
// closed gate with a full budget.
const idleTTL = 60 * time.Second

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

	// mu also serializes the calls into inner, so lastSeen follows the order inner saw them in.
	mu         sync.Mutex
	now        func() time.Time
	backingOff bool
	// lastSeen is when inner last restarted the leg's idleTTL: the last Admit or applied Report.
	lastSeen time.Time
}

// Ticket is one Admit outcome. Pass it to Report once after a real backend attempt.
type Ticket struct {
	// Admitted means the caller may call the backend.
	Admitted bool
	// probe marks an admission granted while the leg was backing off.
	probe bool
	// permit is the utilities generation for this admission. Report counts only when it still matches.
	permit backendbackoff.Permit
}

// New builds a Gate when cfg.PeriodSecs is greater than zero, else returns nil.
// The cooldown is fixed (no exponential growth). Jitter stays unset so a partial utilities Config
// disables jitter. TTL is idleTTL, so the wrapper knows when the utilities gate forgets the leg.
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
		TTL:          idleTTL,
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
		now:        time.Now,
	}, nil
}

// Admit asks the gate whether this request may call the backend.
// The first denied admission logs MsgStarted. Later denials stay silent until a probe succeeds or
// the leg is forgotten after idleTTL.
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
	now := g.now()
	g.forgetIfIdleLocked(now)
	permit, wait, err := g.inner.Allow(g.key)
	if err != nil {
		return Ticket{}, err
	}
	g.lastSeen = now
	if !permit.Allowed() {
		if !g.backingOff {
			g.backingOff = true
			g.log.Warn(g.msgStarted, "retryIn", wait.String(), "reason", "unhealthy")
		}
		return Ticket{}, nil
	}
	// Admitted while backing off: the gate let a probe through.
	return Ticket{Admitted: true, probe: g.backingOff, permit: permit}, nil
}

// Report records a real backend attempt. MsgEnded is logged only when a probe's report is applied.
// A nil gate, an unadmitted ticket, or a stale permit does not log that line.
func (g *Gate) Report(ticket Ticket, success bool) error {
	if g == nil || !ticket.Admitted {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	applied, err := g.inner.Report(ticket.permit, success)
	if err != nil {
		return err
	}
	if applied {
		g.lastSeen = now
	}
	if !success || !ticket.probe || !applied {
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

// BackingOff reports whether the leg is backing off: MsgStarted was logged, and neither a probe's
// success nor idleTTL without an admission has cleared it since.
func (g *Gate) BackingOff() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.forgetIfIdleLocked(g.now())
	return g.backingOff
}

// forgetIfIdleLocked clears backingOff once idleTTL has passed since inner last saw the leg: inner
// has forgotten it, and its next Allow starts from a closed gate. Nothing is logged, because no probe
// showed the backend healthy. Caller holds g.mu.
func (g *Gate) forgetIfIdleLocked(now time.Time) {
	if g.backingOff && !now.Before(g.lastSeen.Add(idleTTL)) {
		g.backingOff = false
	}
}

// Close releases the utilities gate. Later Admit and Report return an error.
func (g *Gate) Close() {
	if g == nil {
		return
	}
	g.inner.Close()
}

// SetNowForTest replaces the clock of the wrapper and of the utilities gate. nil restores time.Now.
// Production callers must not use this.
func (g *Gate) SetNowForTest(now func() time.Time) {
	if g == nil {
		return
	}
	g.inner.SetNowForTest(now)
	g.mu.Lock()
	defer g.mu.Unlock()
	if now == nil {
		now = time.Now
	}
	g.now = now
}

// Inner is the utilities gate, for tests that call it directly.
func (g *Gate) Inner() *backendbackoff.Gate {
	if g == nil {
		return nil
	}
	return g.inner
}
