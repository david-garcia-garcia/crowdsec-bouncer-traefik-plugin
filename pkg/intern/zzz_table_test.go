package intern

import "testing"

func TestIDNameRoundTrip(t *testing.T) {
	table := New()
	id, ok := table.ID("crowdsec")
	if !ok || id == 0 {
		t.Fatalf("ID ok=%v id=%d", ok, id)
	}
	if table.Name(id) != "crowdsec" {
		t.Fatalf("Name %q", table.Name(id))
	}
	again, ok := table.ID("crowdsec")
	if !ok || again != id {
		t.Fatalf("second ID %d ok=%v", again, ok)
	}
}

func TestIDEmptyNameIsZero(t *testing.T) {
	table := New()
	id, ok := table.ID("")
	if !ok || id != 0 || table.Name(0) != "" {
		t.Fatalf("empty id=%d ok=%v", id, ok)
	}
}

func TestIDNilTable(t *testing.T) {
	var table *Table
	id, ok := table.ID("crowdsec")
	if ok || id != 0 || table.Name(1) != "" {
		t.Fatalf("nil ID id=%d ok=%v", id, ok)
	}
}

func TestIDTablesDoNotShareIds(t *testing.T) {
	first := New()
	second := New()
	firstID, _ := first.ID("crowdsec")
	second.ID("other")
	secondID, _ := second.ID("crowdsec")
	if first.Name(firstID) != "crowdsec" || second.Name(firstID) == "crowdsec" {
		t.Fatal("tables must not share snapshots")
	}
	if second.Name(secondID) != "crowdsec" {
		t.Fatalf("second Name %q", second.Name(secondID))
	}
}

func TestIDOverflowDoesNotWrap(t *testing.T) {
	table := New()
	table.FillUntilMaxForTest()
	id, ok := table.ID("overflow")
	if ok || id != 0 {
		t.Fatalf("overflow id=%d ok=%v", id, ok)
	}
	if table.Name(1) != "1" {
		t.Fatalf("full table Name %q", table.Name(1))
	}
}

func TestNameUnknownIdIsEmpty(t *testing.T) {
	table := New()
	if table.Name(9) != "" {
		t.Fatalf("unknown %q", table.Name(9))
	}
}
