package admission

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

const (
	testStarted = "test backoff started"
	testEnded   = "test backoff ended"
)

func newTestGate(t *testing.T) (*Gate, *bytes.Buffer, *time.Time) {
	t.Helper()
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	gate, err := New(Config{
		Leg:        "test",
		PeriodSecs: 10,
		MsgStarted: testStarted,
		MsgEnded:   testEnded,
	}, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)
	now := time.Unix(1_700_000_000, 0)
	gate.Inner().SetNowForTest(func() time.Time { return now })
	return gate, &buf, &now
}

func admit(t *testing.T, gate *Gate) Ticket {
	t.Helper()
	ticket, err := gate.Admit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return ticket
}

func report(t *testing.T, gate *Gate, ticket Ticket, success bool) {
	t.Helper()
	if err := gate.Report(ticket, success); err != nil {
		t.Fatal(err)
	}
}

// trip spends the whole failure budget with consecutive failures.
func trip(t *testing.T, gate *Gate) {
	t.Helper()
	for range TripFailures {
		report(t, gate, admit(t, gate), false)
	}
}

func TestNew_zeroPeriodIsNilGateThatAdmits(t *testing.T) {
	gate, err := New(Config{Leg: "test"}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if gate != nil {
		t.Fatal("period 0 must not build a gate")
	}
	ticket, err := gate.Admit(context.Background())
	if err != nil || !ticket.Admitted {
		t.Fatalf("nil gate must admit, got %+v %v", ticket, err)
	}
	if err := gate.Report(ticket, false); err != nil {
		t.Fatal(err)
	}
	gate.Close()
}

func TestGate_logsStartedOnceAcrossSkippedRequests(t *testing.T) {
	gate, buf, _ := newTestGate(t)
	trip(t, gate)
	for i := range 5 {
		if admit(t, gate).Admitted {
			t.Fatalf("request %d must be skipped after the trip", i)
		}
	}
	if got := strings.Count(buf.String(), testStarted); got != 1 {
		t.Fatalf("started lines=%d want 1\n%s", got, buf.String())
	}
	if strings.Contains(buf.String(), testEnded) {
		t.Fatal("no probe succeeded, ended must not be logged")
	}
	if !gate.BackingOff() {
		t.Fatal("gate must report backing off")
	}
}

func TestGate_successfulProbeLogsEndedOnce(t *testing.T) {
	gate, buf, now := newTestGate(t)
	trip(t, gate)
	if admit(t, gate).Admitted {
		t.Fatal("must skip after the trip")
	}
	*now = now.Add(11 * time.Second)
	probe := admit(t, gate)
	if !probe.Admitted {
		t.Fatal("cooldown elapsed: the probe must be admitted")
	}
	report(t, gate, probe, true)
	next := admit(t, gate)
	report(t, gate, next, true)
	if got := strings.Count(buf.String(), testEnded); got != 1 {
		t.Fatalf("ended lines=%d want 1\n%s", got, buf.String())
	}
	if gate.BackingOff() {
		t.Fatal("gate must be healthy after a successful probe")
	}
}

func TestGate_failedProbeStaysSilent(t *testing.T) {
	gate, buf, now := newTestGate(t)
	trip(t, gate)
	_ = admit(t, gate)
	*now = now.Add(11 * time.Second)
	report(t, gate, admit(t, gate), false)
	if admit(t, gate).Admitted {
		t.Fatal("failed probe must reopen the backoff")
	}
	if got := strings.Count(buf.String(), testStarted); got != 1 {
		t.Fatalf("started lines=%d want 1\n%s", got, buf.String())
	}
	if strings.Contains(buf.String(), testEnded) {
		t.Fatal("failed probe must not log ended")
	}
}

// A probe whose lease expired reports after a newer probe was admitted. Only the newer
// probe's permit matches the gate, so only its success may log ended.
func TestGate_expiredProbeSuccessDoesNotLogEnded(t *testing.T) {
	gate, buf, now := newTestGate(t)
	trip(t, gate)
	if admit(t, gate).Admitted {
		t.Fatal("must skip after the trip")
	}
	*now = now.Add(11 * time.Second)
	expired := admit(t, gate)
	if !expired.Admitted {
		t.Fatal("cooldown elapsed: the first probe must be admitted")
	}
	*now = now.Add(11 * time.Second)
	probe := admit(t, gate)
	if !probe.Admitted {
		t.Fatal("probe lease expired: a new probe must be admitted")
	}
	report(t, gate, expired, true)
	if strings.Contains(buf.String(), testEnded) {
		t.Fatalf("an expired probe's success must not log ended\n%s", buf.String())
	}
	if !gate.BackingOff() {
		t.Fatal("an expired probe's success must leave the gate backing off")
	}
	report(t, gate, probe, true)
	if got := strings.Count(buf.String(), testEnded); got != 1 {
		t.Fatalf("ended lines=%d want 1\n%s", got, buf.String())
	}
	if gate.BackingOff() {
		t.Fatal("the current probe's success must clear backoff")
	}
}

// A ticket admitted before the trip reports success while a probe is in flight. The gate
// ignores it, so the probe still decides the outcome.
func TestGate_staleTicketAfterAdmittedProbeDoesNotLogEnded(t *testing.T) {
	gate, buf, now := newTestGate(t)
	stale := admit(t, gate)
	trip(t, gate)
	if admit(t, gate).Admitted {
		t.Fatal("must skip after the trip")
	}
	*now = now.Add(11 * time.Second)
	probe := admit(t, gate)
	if !probe.Admitted {
		t.Fatal("cooldown elapsed: the probe must be admitted")
	}
	report(t, gate, stale, true)
	if strings.Contains(buf.String(), testEnded) {
		t.Fatal("a ticket admitted before the trip must not log ended after a probe is in flight")
	}
	if !gate.BackingOff() {
		t.Fatal("a stale success must leave the gate backing off")
	}
	report(t, gate, probe, true)
	if got := strings.Count(buf.String(), testEnded); got != 1 {
		t.Fatalf("ended lines=%d want 1\n%s", got, buf.String())
	}
	if gate.BackingOff() {
		t.Fatal("the real probe's success must clear backoff")
	}
}

// utilitiesIdleTTL is the utilities gate's default idle TTL: a leg without an Allow or an applied
// Report for that long is dropped.
const utilitiesIdleTTL = time.Minute

// The utilities gate forgets a leg idle for utilitiesIdleTTL. Its next outage is a new trip, so it logs
// started again, even though no probe ever succeeded to log ended.
func TestGate_forgottenLegLogsStartedOnTheNextTrip(t *testing.T) {
	gate, buf, now := newTestGate(t)
	trip(t, gate)
	if admit(t, gate).Admitted {
		t.Fatal("must skip after the trip")
	}
	if got := strings.Count(buf.String(), testStarted); got != 1 {
		t.Fatalf("started lines=%d want 1\n%s", got, buf.String())
	}
	*now = now.Add(utilitiesIdleTTL)
	if gate.BackingOff() {
		t.Fatal("a leg idle for utilitiesIdleTTL is forgotten: it must not report backing off")
	}
	for i := range TripFailures {
		ticket := admit(t, gate)
		if !ticket.Admitted {
			t.Fatalf("request %d: a forgotten leg starts closed with a full budget", i)
		}
		report(t, gate, ticket, false)
	}
	if admit(t, gate).Admitted {
		t.Fatal("must skip after the second trip")
	}
	if got := strings.Count(buf.String(), testStarted); got != 2 {
		t.Fatalf("started lines=%d want 2\n%s", got, buf.String())
	}
	if strings.Contains(buf.String(), testEnded) {
		t.Fatalf("no probe succeeded, ended must not be logged\n%s", buf.String())
	}
	if !gate.BackingOff() {
		t.Fatal("gate must report backing off after the second trip")
	}
}

// Admit alone notices the dropped leg: the first admission after utilitiesIdleTTL is not a probe, so
// the next trip logs started again even when nothing called BackingOff in between.
func TestGate_forgottenLegSeenByAdmitAlone(t *testing.T) {
	gate, buf, now := newTestGate(t)
	trip(t, gate)
	if admit(t, gate).Admitted {
		t.Fatal("must skip after the trip")
	}
	*now = now.Add(utilitiesIdleTTL)
	trip(t, gate)
	if admit(t, gate).Admitted {
		t.Fatal("must skip after the second trip")
	}
	if got := strings.Count(buf.String(), testStarted); got != 2 {
		t.Fatalf("started lines=%d want 2\n%s", got, buf.String())
	}
	if strings.Contains(buf.String(), testEnded) {
		t.Fatalf("no probe succeeded, ended must not be logged\n%s", buf.String())
	}
}

// Each admission restarts utilitiesIdleTTL: an outage that outlasts it with failed probes in between is still
// one outage and one started line.
func TestGate_outageWithinIdleTTLLogsStartedOnce(t *testing.T) {
	gate, buf, now := newTestGate(t)
	trip(t, gate)
	if admit(t, gate).Admitted {
		t.Fatal("must skip after the trip")
	}
	*now = now.Add(utilitiesIdleTTL - time.Second)
	probe := admit(t, gate)
	if !probe.Admitted {
		t.Fatal("cooldown elapsed: the probe must be admitted")
	}
	report(t, gate, probe, false)
	if admit(t, gate).Admitted {
		t.Fatal("a failed probe must reopen the backoff")
	}
	*now = now.Add(utilitiesIdleTTL - time.Second)
	if !gate.BackingOff() {
		t.Fatal("the failed probe was within utilitiesIdleTTL: the gate must still be backing off")
	}
	probe = admit(t, gate)
	if !probe.Admitted {
		t.Fatal("cooldown elapsed: the second probe must be admitted")
	}
	report(t, gate, probe, false)
	if admit(t, gate).Admitted {
		t.Fatal("a failed probe must reopen the backoff")
	}
	if got := strings.Count(buf.String(), testStarted); got != 1 {
		t.Fatalf("started lines=%d want 1\n%s", got, buf.String())
	}
	if strings.Contains(buf.String(), testEnded) {
		t.Fatal("failed probes must not log ended")
	}
}

func TestGate_inFlightSuccessDoesNotEndBackoff(t *testing.T) {
	gate, buf, _ := newTestGate(t)
	inFlight := admit(t, gate)
	trip(t, gate)
	if admit(t, gate).Admitted {
		t.Fatal("must skip after the trip")
	}
	report(t, gate, inFlight, true)
	if strings.Contains(buf.String(), testEnded) {
		t.Fatal("a request admitted before the trip must not end the backoff")
	}
	if !gate.BackingOff() {
		t.Fatal("gate must still be backing off")
	}
}

func TestGate_failuresBelowThresholdDoNotLog(t *testing.T) {
	gate, buf, _ := newTestGate(t)
	for i := range TripFailures - 1 {
		ticket := admit(t, gate)
		if !ticket.Admitted {
			t.Fatalf("request %d must be admitted under the threshold", i)
		}
		report(t, gate, ticket, false)
	}
	if buf.Len() != 0 {
		t.Fatalf("no transition expected, got\n%s", buf.String())
	}
}

func TestGate_tripsOnTheFifthConsecutiveFailure(t *testing.T) {
	gate, _, _ := newTestGate(t)
	for i := range TripFailures - 1 {
		report(t, gate, admit(t, gate), false)
		if !admit(t, gate).Admitted {
			t.Fatalf("failure %d is under the budget: the next request must be admitted", i+1)
		}
	}
	report(t, gate, admit(t, gate), false)
	if admit(t, gate).Admitted {
		t.Fatalf("failure %d spends the budget: the next request must be skipped", TripFailures)
	}
}

func TestGate_cooldownDoesNotGrowAfterAFailedProbe(t *testing.T) {
	gate, _, now := newTestGate(t)
	trip(t, gate)
	*now = now.Add(11 * time.Second)
	report(t, gate, admit(t, gate), false)
	*now = now.Add(11 * time.Second)
	if !admit(t, gate).Admitted {
		t.Fatal("the cooldown is fixed: a second probe must be admitted after the same period")
	}
}

func TestGate_canceledRequestDoesNotTakeTheProbe(t *testing.T) {
	gate, _, now := newTestGate(t)
	trip(t, gate)
	*now = now.Add(11 * time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ticket, err := gate.Admit(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled request: err=%v want context.Canceled", err)
	}
	if ticket.Admitted {
		t.Fatal("a canceled request must not be admitted")
	}
	if !admit(t, gate).Admitted {
		t.Fatal("the canceled request must leave the probe to the next request")
	}
}
