package decisionscope

import "testing"

func TestRemediationKindBareLetter(t *testing.T) {
	if RemediationKind("t") != "t" {
		t.Fatal("bare letter")
	}
	if RemediationKind("") != "" {
		t.Fatal("empty")
	}
	if RemediationKind("ban") != "ban" {
		t.Fatalf("unknown %q", RemediationKind("ban"))
	}
}
