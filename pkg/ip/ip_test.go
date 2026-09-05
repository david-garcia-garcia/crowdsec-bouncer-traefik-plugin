package ip

import (
	"log/slog"
	"testing"
)

func TestInNetwork(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		network string
		want    bool
		wantErr bool
	}{
		{name: "CIDR contains", addr: "10.1.2.3", network: "10.0.0.0/8", want: true},
		{name: "CIDR misses", addr: "11.0.0.1", network: "10.0.0.0/8", want: false},
		{name: "bare IP equals", addr: "1.2.3.4", network: "1.2.3.4", want: true},
		{name: "bare IP differs", addr: "1.2.3.4", network: "1.2.3.5", want: false},
		{name: "bad address", addr: "not-an-ip", network: "10.0.0.0/8", wantErr: true},
		{name: "bad network", addr: "1.2.3.4", network: "not-a-net", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := InNetwork(tt.addr, tt.network)
			if (err != nil) != tt.wantErr {
				t.Fatalf("InNetwork(%q, %q) err=%v wantErr=%v", tt.addr, tt.network, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Fatalf("InNetwork(%q, %q)=%v want %v", tt.addr, tt.network, got, tt.want)
			}
		})
	}
}

func TestCheckerContains(t *testing.T) {
	log := slog.Default()

	t.Run("CIDR hit and miss", func(t *testing.T) {
		checker, err := NewChecker(log, []string{"10.0.0.0/8"})
		if err != nil {
			t.Fatal(err)
		}
		ok, err := checker.Contains("10.1.2.3")
		if err != nil || !ok {
			t.Fatalf("Contains 10.1.2.3 = %v, %v want true", ok, err)
		}
		ok, err = checker.Contains("203.0.113.10")
		if err != nil || ok {
			t.Fatalf("Contains 203.0.113.10 = %v, %v want false", ok, err)
		}
	})

	t.Run("bare host", func(t *testing.T) {
		checker, err := NewChecker(log, []string{"192.0.2.1"})
		if err != nil {
			t.Fatal(err)
		}
		ok, err := checker.Contains("192.0.2.1")
		if err != nil || !ok {
			t.Fatalf("Contains bare host = %v, %v want true", ok, err)
		}
		ok, err = checker.Contains("192.0.2.2")
		if err != nil || ok {
			t.Fatalf("Contains other host = %v, %v want false", ok, err)
		}
	})

	t.Run("overlapping any-match", func(t *testing.T) {
		checker, err := NewChecker(log, []string{"192.168.0.0/16", "192.168.1.0/24"})
		if err != nil {
			t.Fatal(err)
		}
		ok, err := checker.Contains("192.168.1.5")
		if err != nil || !ok {
			t.Fatalf("Contains overlapping = %v, %v want true", ok, err)
		}
	})

	t.Run("empty list", func(t *testing.T) {
		checker, err := NewChecker(log, []string{})
		if err != nil {
			t.Fatal(err)
		}
		ok, err := checker.Contains("10.1.2.3")
		if err != nil || ok {
			t.Fatalf("empty Contains = %v, %v want false", ok, err)
		}
	})

	t.Run("invalid CIDR", func(t *testing.T) {
		_, err := NewChecker(log, []string{"192.168.1.0/33"})
		if err == nil {
			t.Fatal("expected error for 192.168.1.0/33")
		}
	})
}

func TestCheckerContainsCatchAllFamily(t *testing.T) {
	log := slog.Default()

	t.Run("IPv4 catch-all does not match IPv6", func(t *testing.T) {
		checker, err := NewChecker(log, []string{"0.0.0.0/0"})
		if err != nil {
			t.Fatal(err)
		}
		ok, err := checker.Contains("2001:db8::1")
		if err != nil || ok {
			t.Fatalf("Contains IPv6 under 0.0.0.0/0 = %v, %v want false", ok, err)
		}
		ok, err = checker.Contains("203.0.113.10")
		if err != nil || !ok {
			t.Fatalf("Contains IPv4 under 0.0.0.0/0 = %v, %v want true", ok, err)
		}
	})

	t.Run("IPv6 catch-all does not match IPv4", func(t *testing.T) {
		checker, err := NewChecker(log, []string{"::/0"})
		if err != nil {
			t.Fatal(err)
		}
		ok, err := checker.Contains("203.0.113.10")
		if err != nil || ok {
			t.Fatalf("Contains IPv4 under ::/0 = %v, %v want false", ok, err)
		}
		ok, err = checker.Contains("2001:db8::1")
		if err != nil || !ok {
			t.Fatalf("Contains IPv6 under ::/0 = %v, %v want true", ok, err)
		}
	})
}
