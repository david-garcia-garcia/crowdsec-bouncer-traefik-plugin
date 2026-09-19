package decisionscope

import (
	"net"
	"testing"
	"time"
)

func TestLookupLiveSnapshotSkipsRangeOnIpBan(t *testing.T) {
	snapshot := map[string]LiveSlot{
		"203.0.113.10": {Word: packWord(BannedValue, 1), ExpiresAt: time.Now().Unix() + 60},
	}
	membership := MembershipFromIndex("10.0.0.0/8=" + CaptchaValue)
	kind, _, _, err := LookupStreamMapRemediation(snapshot, "203.0.113.10", net.ParseIP("203.0.113.10"), nil, membership)
	if err != nil || kind != BannedValue {
		t.Fatalf("kind %q err %v", kind, err)
	}
}

func TestPublishLiveSnapshotDropsExpired(t *testing.T) {
	now := int64(1_000_000)
	snapshot := map[string]LiveSlot{
		"1.2.3.4": {Word: packWord(BannedValue, 0), ExpiresAt: now - 1},
		"5.6.7.8": {Word: packWord(BannedValue, 0), ExpiresAt: now + 60},
	}
	for key, slot := range snapshot {
		if slot.ExpiresAt > 0 && slot.ExpiresAt <= now {
			delete(snapshot, key)
		}
	}
	if _, ok := snapshot["1.2.3.4"]; ok {
		t.Fatal("expired slot must drop on publish")
	}
	if _, ok := snapshot["5.6.7.8"]; !ok {
		t.Fatal("future slot must remain")
	}
}
