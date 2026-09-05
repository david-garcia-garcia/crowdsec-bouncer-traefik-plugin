package ip

import "testing"

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
