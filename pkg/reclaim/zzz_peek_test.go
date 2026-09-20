package reclaim

import (
	"context"
	"log/slog"
	"testing"
	"time"
)

func TestShim_PeekMissIsOkFalse(t *testing.T) {
	ResetForTestWith(200 * time.Millisecond)
	t.Cleanup(func() { ResetForTest() })

	_, _, ok := Peek("missing")
	if ok {
		t.Fatal("Peek of an absent key must be ok=false")
	}
}

func TestShim_PeekBusyIsOkFalseWithoutWaiting(t *testing.T) {
	ResetForTestWith(200 * time.Millisecond)
	t.Cleanup(func() { ResetForTest() })

	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := OpenWithHooks(context.Background(), "busy", slog.Default(), func() (any, Hooks, error) {
			close(started)
			<-release
			return "v", Hooks{}, nil
		})
		done <- err
	}()
	<-started
	peeked := make(chan struct{})
	go func() {
		_, _, busyOK := Peek("busy")
		if busyOK {
			t.Error("Peek of a busy slot must be ok=false")
		}
		close(peeked)
	}()
	select {
	case <-peeked:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Peek must not wait on a busy slot")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestShim_PeekAwakeDoesNotBind(t *testing.T) {
	ResetForTestWith(200 * time.Millisecond)
	t.Cleanup(func() { ResetForTest() })

	ctx, cancel := context.WithCancel(context.Background())
	value, err := OpenWithHooks(ctx, "awake", slog.Default(), func() (any, Hooks, error) {
		return "awake-v", Hooks{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	got, state, ok := Peek("awake")
	if !ok || state != Awake || got != value {
		t.Fatalf("Peek awake: ok=%v state=%v got=%v", ok, state, got)
	}
	cancel()
	if !waitPeekState(t, "awake", Asleep) {
		t.Fatal("cancelling the only Open context must Sleep; Peek must not have bound")
	}
}

func TestShim_PeekAsleepLeavesGraceRunning(t *testing.T) {
	ResetForTestWith(200 * time.Millisecond)
	t.Cleanup(func() { ResetForTest() })

	closed := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	_, err := OpenWithHooks(ctx, "asleep", slog.Default(), func() (any, Hooks, error) {
		return "asleep-v", Hooks{Close: func() { close(closed) }}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if !waitPeekState(t, "asleep", Asleep) {
		t.Fatal("last holder gone must Peek Asleep before grace ends")
	}
	select {
	case <-closed:
		t.Fatal("Peek of a sleeping key must not stop grace Close")
	case <-time.After(50 * time.Millisecond):
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("grace must still expire and Close")
	}
	_, _, ok := Peek("asleep")
	if ok {
		t.Fatal("after grace Close Peek must be ok=false")
	}
}

// waitPeekState reports whether Peek reached want before the deadline.
func waitPeekState(t *testing.T, key string, want State) bool {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, state, ok := Peek(key)
		if ok && state == want {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return false
}
