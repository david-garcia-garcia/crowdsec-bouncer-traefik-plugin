package reclaim

import (
	"context"
	"log/slog"
	"testing"
	"time"
)

func TestTable_PeekLivePrefixFindsLiveIgnoresSleeper(t *testing.T) {
	tab := New(Config{Grace: time.Second})
	liveCtx, liveCancel := context.WithCancel(context.Background())
	t.Cleanup(liveCancel)
	sleepCtx, sleepCancel := context.WithCancel(context.Background())
	if _, err := tab.Open(sleepCtx, "sess:sleep", slog.Default(), func() (any, error) { return "s", nil }, Hooks{}); err != nil {
		t.Fatal(err)
	}
	sleepCancel()
	time.Sleep(20 * time.Millisecond)
	if _, err := tab.Open(liveCtx, "sess:live", slog.Default(), func() (any, error) { return "l", nil }, Hooks{}); err != nil {
		t.Fatal(err)
	}
	view := tab.PeekLivePrefix("sess:")
	if !view.OK || view.Key != "sess:live" || view.Value != "l" {
		t.Fatalf("PeekLivePrefix live: %+v", view)
	}
	if tab.PeekLivePrefix("other:").OK {
		t.Fatal("PeekLivePrefix must miss a different stem")
	}
	if tab.PeekLivePrefix("").OK {
		t.Fatal("empty prefix must miss")
	}
}

func TestTable_PeekDuringSleep(t *testing.T) {
	tab := New(Config{Grace: time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	if _, err := tab.Open(ctx, "k", slog.Default(), func() (any, error) { return 1, nil }, Hooks{}); err != nil {
		t.Fatal(err)
	}
	cancel()
	time.Sleep(20 * time.Millisecond)
	view := tab.Peek("k")
	if !view.OK || view.Holders != 0 || !view.Sleeping || view.Value != 1 {
		t.Fatalf("Peek during sleep: %+v", view)
	}
}

func TestTable_OpenWithHooksReclaimsDuringGrace(t *testing.T) {
	tab := New(Config{Grace: 200 * time.Millisecond})
	creates := 0
	create := func() (any, Hooks, error) {
		creates++
		return "v", Hooks{}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	first, err := tab.OpenWithHooks(ctx, "k", slog.Default(), create)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	time.Sleep(20 * time.Millisecond)
	second, err := tab.OpenWithHooks(context.Background(), "k", slog.Default(), create)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || creates != 1 {
		t.Fatalf("grace reclaim: first=%v second=%v creates=%d", first, second, creates)
	}
}
