package admission

import (
	"bytes"
	"context"
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
