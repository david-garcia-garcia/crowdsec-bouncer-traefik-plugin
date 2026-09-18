package decisionscope

import "testing"

func TestRemediationKindStripsOrigin(t *testing.T) {
	stored := RemediationWithOrigin("t", "crowdsec")
	if RemediationKind(stored) != "t" {
		t.Fatalf("kind %q", RemediationKind(stored))
	}
	if RemediationOrigin(stored) != "crowdsec" {
		t.Fatalf("origin %q", RemediationOrigin(stored))
	}
	if RemediationKind("t") != "t" {
		t.Fatal("bare letter")
	}
	if RemediationOrigin("t") != "" {
		t.Fatal("bare origin")
	}
}

func TestPackWordRoundTrip(t *testing.T) {
	word := PackWord(BannedValue, 12)
	kind, originID := UnpackWord(word)
	if kind != BannedValue || originID != 12 {
		t.Fatalf("kind %q id %d", kind, originID)
	}
}

func TestSplitStoredPackedLine(t *testing.T) {
	kind, leftover, originID := SplitStoredRemediation(PackedRemediationLine(BannedValue, 12))
	if kind != BannedValue || leftover != "" || originID != 12 {
		t.Fatalf("kind %q leftover %q id %d", kind, leftover, originID)
	}
}
