package cache

import (
	"log/slog"
	"strings"
	"testing"
)

// TestHunt_GetDebugUsesAttributes fails if Get still Sprintfs the key into msg.
func TestHunt_GetDebugUsesAttributes(t *testing.T) {
	log, sink := newTestLogSink(slog.LevelDebug)
	client := &Client{cache: &localCache{}, log: log}
	_, _ = client.Get("10.0.0.1")
	logged := sink.String()
	if !strings.Contains(logged, `"msg":"cache:Get"`) {
		t.Fatalf("want msg cache:Get, got %s", logged)
	}
	if strings.Contains(logged, "cache:Get key:") {
		t.Fatalf("interpolated Get msg: %s", logged)
	}
	if !strings.Contains(logged, `"key":"10.0.0.1"`) {
		t.Fatalf("want key attribute, got %s", logged)
	}
}

// TestHunt_GetManyDebugUsesAttributes fails if GetMany still Sprintfs keys into msg.
func TestHunt_GetManyDebugUsesAttributes(t *testing.T) {
	log, sink := newTestLogSink(slog.LevelDebug)
	client := &Client{cache: &localCache{}, log: log}
	_, _ = client.GetMany([]string{"10.0.0.1", "scope:country:FR"})
	logged := sink.String()
	if !strings.Contains(logged, `"msg":"cache:GetMany"`) {
		t.Fatalf("want msg cache:GetMany, got %s", logged)
	}
	if strings.Contains(logged, "cache:GetMany keys:") {
		t.Fatalf("interpolated GetMany msg: %s", logged)
	}
	if !strings.Contains(logged, `"keys":["10.0.0.1","scope:country:FR"]`) {
		t.Fatalf("want keys attribute, got %s", logged)
	}
}
