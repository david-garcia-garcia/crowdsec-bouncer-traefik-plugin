package health

import (
	"log/slog"
	"sync"
	"testing"
	"time"
)

func TestNew_StartsWindowClockWhenWindowSet(t *testing.T) {
	ht := New(time.Second, 10*time.Second, 5, slog.Default())
	if ht.lastFailureReset.IsZero() {
		t.Fatal("lastFailureReset must start at New when a window is set")
	}
}

func TestNew_ZeroWindowLeavesClockUnset(t *testing.T) {
	ht := New(time.Second, 0, 5, slog.Default())
	if !ht.lastFailureReset.IsZero() {
		t.Fatal("lastFailureReset must stay zero when the window is 0")
	}
}

func TestNew_InitialisesFieldsCorrectly(t *testing.T) {
	ht := New(5*time.Second, 10*time.Second, 2, slog.Default())
	if ht.IsUnhealthy() {
		t.Fatal("new tracker must be healthy")
	}
	if ht.RecordFailure() || ht.IsUnhealthy() {
		t.Fatal("first failure at threshold 2 must not trip")
	}
	if !ht.RecordFailure() || !ht.IsUnhealthy() {
		t.Fatal("second failure at threshold 2 must trip")
	}
}

func TestRecordFailure_UnderThresholdDoesNotTrip_AtThresholdTrips(t *testing.T) {
	ht := New(100*time.Millisecond, 0, 3, slog.Default())
	if ht.RecordFailure() || ht.IsUnhealthy() {
		t.Fatal("failure 1 must not trip")
	}
	if ht.RecordFailure() || ht.IsUnhealthy() {
		t.Fatal("failure 2 must not trip")
	}
	if !ht.RecordFailure() || !ht.IsUnhealthy() {
		t.Fatal("failure 3 must trip")
	}
}

func TestRecordFailure_WindowReset(t *testing.T) {
	window := 50 * time.Millisecond
	ht := New(time.Second, window, 2, slog.Default())
	ht.RecordFailure()
	if ht.IsUnhealthy() {
		t.Fatal("one failure must not trip threshold 2")
	}
	time.Sleep(window + 10*time.Millisecond)
	ht.RecordFailure()
	if ht.IsUnhealthy() {
		t.Fatal("count must reset after the window")
	}
	if !ht.RecordFailure() || !ht.IsUnhealthy() {
		t.Fatal("second failure in the new window must trip")
	}
}

func TestIsUnhealthy_TrueWhileInBackoff_FalseAfterExpiry(t *testing.T) {
	backoff := 50 * time.Millisecond
	ht := New(backoff, 0, 1, slog.Default())
	ht.RecordFailure()
	if !ht.IsUnhealthy() {
		t.Fatal("must be unhealthy during backoff")
	}
	time.Sleep(backoff + 20*time.Millisecond)
	if ht.IsUnhealthy() {
		t.Fatal("must recover after backoff")
	}
}

func TestRecordFailure_NegativeThresholdNeverTrips(t *testing.T) {
	ht := New(time.Second, 0, -1, slog.Default())
	for range 100 {
		if ht.RecordFailure() || ht.IsUnhealthy() {
			t.Fatal("threshold -1 must never trip")
		}
	}
}

func TestRecordFailure_ZeroTimeoutNeverTrips(t *testing.T) {
	ht := New(0, 0, 1, slog.Default())
	if ht.RecordFailure() || ht.IsUnhealthy() {
		t.Fatal("timeout 0 must never skip")
	}
}

func TestRecordFailure_ZeroThresholdFirstFailureTrips(t *testing.T) {
	ht := New(100*time.Millisecond, 0, 0, slog.Default())
	if !ht.RecordFailure() || !ht.IsUnhealthy() {
		t.Fatal("threshold 0 must trip on the first failure")
	}
}

func TestNewFromSeconds(t *testing.T) {
	ht := NewFromSeconds(30, 30, 5, slog.Default())
	if ht.IsUnhealthy() {
		t.Fatal("new tracker from seconds must be healthy")
	}
}

func TestRecordFailure_ConcurrentNoRace(_ *testing.T) {
	ht := New(10*time.Millisecond, 5*time.Millisecond, 1000, slog.Default())
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				ht.RecordFailure()
				ht.IsUnhealthy()
			}
		}()
	}
	wg.Wait()
}
