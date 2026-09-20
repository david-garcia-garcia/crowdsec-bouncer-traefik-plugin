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
