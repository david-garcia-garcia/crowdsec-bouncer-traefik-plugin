package cache

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
