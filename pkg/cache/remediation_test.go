package cache

import "testing"

func TestRemediationKindStripsOrigin(t *testing.T) {
	stored := RemediationWithOrigin(BannedValue, "crowdsec")
	if RemediationKind(stored) != BannedValue {
		t.Fatalf("kind %q", RemediationKind(stored))
	}
	if RemediationOrigin(stored) != "crowdsec" {
		t.Fatalf("origin %q", RemediationOrigin(stored))
	}
	if RemediationKind(BannedValue) != BannedValue {
		t.Fatal("bare letter")
	}
	if RemediationOrigin(BannedValue) != "" {
		t.Fatal("bare origin")
	}
}
