package reclaim

import (
	"context"
	"log/slog"
	"testing"
	"time"
)

func TestShim_ProcessGraceAndOpenWithHooks(t *testing.T) {
	if ProcessGrace != 30*time.Second {
		t.Fatalf("ProcessGrace: %v", ProcessGrace)
	}
	ResetForTestWith(200 * time.Millisecond)
	t.Cleanup(func() { ResetForTest() })

	creates := 0
	create := func() (any, Hooks, error) {
		creates++
		return "v", Hooks{}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	first, err := OpenWithHooks(ctx, "k", slog.Default(), create)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	time.Sleep(20 * time.Millisecond)
	second, err := OpenWithHooks(context.Background(), "k", slog.Default(), create)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || creates != 1 {
		t.Fatalf("grace reclaim: first=%v second=%v creates=%d", first, second, creates)
	}
}

func TestEnsureProcessGraceFirstWins(t *testing.T) {
	ResetForTestWith(ProcessGrace)
	t.Cleanup(func() { ResetForTest() })

	installed := Default()
	EnsureProcessGrace(time.Hour)
	if Default() != installed {
		t.Fatal("Ensure after Default must keep the table")
	}

	defaultMu.Lock()
	installed.Reset()
	defaultTable = nil
	defaultMu.Unlock()

	EnsureProcessGrace(0)
	zero := Default()
	EnsureProcessGrace(time.Hour)
	if Default() != zero {
		t.Fatal("second Ensure must not replace the table")
	}
}
