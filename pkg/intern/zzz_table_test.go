package intern

import "testing"

func TestInternRoundTrip(t *testing.T) {
	table := New()
	id, ok := table.Intern("crowdsec")
	if !ok || id == 0 {
		t.Fatalf("intern ok=%v id=%d", ok, id)
	}
	if table.Name(id) != "crowdsec" {
		t.Fatalf("Name %q", table.Name(id))
	}
	again, ok := table.Intern("crowdsec")
	if !ok || again != id {
		t.Fatalf("second intern %d ok=%v", again, ok)
	}
}

func TestInternEmptyNameIsZero(t *testing.T) {
	table := New()
	id, ok := table.Intern("")
	if !ok || id != 0 || table.Name(0) != "" {
		t.Fatalf("empty id=%d ok=%v", id, ok)
	}
}

func TestInternNilTable(t *testing.T) {
	var table *Table
	id, ok := table.Intern("crowdsec")
	if ok || id != 0 || table.Name(1) != "" {
		t.Fatalf("nil intern id=%d ok=%v", id, ok)
	}
}

func TestInternTablesDoNotShareIds(t *testing.T) {
	first := New()
	second := New()
	firstID, _ := first.Intern("crowdsec")
	second.Intern("other")
	secondID, _ := second.Intern("crowdsec")
	if first.Name(firstID) != "crowdsec" || second.Name(firstID) == "crowdsec" {
		t.Fatal("tables must not share snapshots")
	}
	if second.Name(secondID) != "crowdsec" {
		t.Fatalf("second Name %q", second.Name(secondID))
	}
}

func TestInternOverflowDoesNotWrap(t *testing.T) {
	table := New()
	names := make([]string, 65536)
	names[0] = ""
	for i := 1; i < 65536; i++ {
		names[i] = "filled"
	}
	table.ReplaceNamesForTest(names)
	id, ok := table.Intern("overflow")
	if ok || id != 0 {
		t.Fatalf("overflow id=%d ok=%v", id, ok)
	}
	if table.Name(1) != "filled" {
		t.Fatalf("full table Name %q", table.Name(1))
	}
}

func TestNameUnknownIdIsEmpty(t *testing.T) {
	table := New()
	if table.Name(9) != "" {
		t.Fatalf("unknown %q", table.Name(9))
	}
}
