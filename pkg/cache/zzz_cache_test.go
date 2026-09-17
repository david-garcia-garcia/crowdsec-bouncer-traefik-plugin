package cache

import (
	"testing"

	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func Test_Get(t *testing.T) {
	IPInCache := "10.0.0.10"
	IPNotInCache := "10.0.0.20"
	client := &Client{cache: &localCache{}, log: logger.New("INFO", "")}
	client.Set(IPInCache, "t", 10)
	type args struct {
		clientIP string
	}
	tests := []struct {
		name     string
		args     args
		want     string
		wantErr  bool
		valueErr string
	}{
		{name: "Fetch Known valid IP", args: args{clientIP: IPInCache}, want: "t", wantErr: false, valueErr: ""},
		{name: "Fetch Unknown valid IP", args: args{clientIP: IPNotInCache}, want: "", wantErr: true, valueErr: CacheMiss},
		{name: "Fetch invalid value", args: args{clientIP: "test"}, want: "", wantErr: true, valueErr: CacheMiss},
		{name: "Fetch empty value", args: args{clientIP: ""}, want: "", wantErr: true, valueErr: CacheMiss},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := client.Get(tt.args.clientIP)
			if (err != nil) != tt.wantErr {
				t.Errorf("Get() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Get() = %v, want %v", got, tt.want)
				return
			}
			if tt.valueErr != "" && tt.valueErr != err.Error() {
				t.Errorf("Get() err = %v, want %v", err.Error(), tt.valueErr)
			}
		})
	}
}

func Test_Set(t *testing.T) {
	client := &Client{cache: &localCache{}, log: logger.New("INFO", "")}
	IPInCache := "10.0.0.11"
	type args struct {
		clientIP string
		value    string
		duration int64
	}

	tests := []struct {
		name     string
		args     args
		want     string
		wantErr  bool
		valueErr string
	}{
		{name: "Set valid IP in local cache for 0 sec", args: args{clientIP: IPInCache, value: "t", duration: 0}, want: "", wantErr: true, valueErr: CacheMiss},
		{name: "Set valid IP in local cache for 10 sec", args: args{clientIP: IPInCache, value: "t", duration: 10}, want: "t", wantErr: false, valueErr: ""},
		{name: "Set valid IP in local cache for 10 sec", args: args{clientIP: IPInCache, value: "f", duration: 10}, want: "f", wantErr: false, valueErr: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client.Set(tt.args.clientIP, tt.args.value, tt.args.duration)
			got, err := client.Get(tt.args.clientIP)
			if (err != nil) != tt.wantErr {
				t.Errorf("Set() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Set() = %v, want %v", got, tt.want)
				return
			}
			if tt.valueErr != "" && tt.valueErr != err.Error() {
				t.Errorf("Set() err = %v, want %v", err.Error(), tt.valueErr)
			}
		})
	}
}

func Test_Delete(t *testing.T) {
	IPInCache := "10.0.0.12"
	IPNotInCache := "10.0.0.22"
	client := &Client{cache: &localCache{}, log: logger.New("INFO", "")}
	client.Set(IPInCache, "t", 10)
	type args struct {
		clientIP string
	}

	tests := []struct {
		name     string
		args     args
		want     string
		wantErr  bool
		valueErr string
	}{
		{name: "Delete Known valid IP", args: args{clientIP: IPInCache}, want: "", wantErr: true, valueErr: CacheMiss},
		{name: "Delete Unknown valid IP", args: args{clientIP: IPNotInCache}, want: "", wantErr: true, valueErr: CacheMiss},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client.Delete(tt.args.clientIP)
			got, err := client.Get(tt.args.clientIP)
			if (err != nil) != tt.wantErr {
				t.Errorf("Delete() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Delete() = %v, want %v", got, tt.want)
				return
			}
			if tt.valueErr != "" && tt.valueErr != err.Error() {
				t.Errorf("Delete() err = %v, want %v", err.Error(), tt.valueErr)
			}
		})
	}
}

func Test_memoryClientsDoNotShare(t *testing.T) {
	a := &Client{}
	b := &Client{}
	a.New(logger.New("INFO", ""))
	b.New(logger.New("INFO", ""))
	a.Set("1.2.3.4", "t", 10)
	got, err := b.Get("1.2.3.4")
	if err == nil || got != "" {
		t.Fatalf("client B got %q err %v, want miss", got, err)
	}
	if err.Error() != CacheMiss {
		t.Fatalf("client B err %v, want %s", err, CacheMiss)
	}
	a.Close()
	b.Close()
}

func Test_ClientCloseMemory(_ *testing.T) {
	client := &Client{}
	client.New(logger.New("INFO", ""))
	client.Close()
	client.Close()
	var empty *Client
	empty.Close()
}

func Test_GetMany(t *testing.T) {
	client := &Client{cache: &localCache{}, log: logger.New("INFO", "")}
	client.Set("a", "t", 10)
	client.Set("b", "c", 10)
	got, err := client.GetMany([]string{"a", "missing", "b", ""})
	if err != nil {
		t.Fatalf("GetMany err %v", err)
	}
	if got["a"] != "t" || got["b"] != "c" {
		t.Fatalf("GetMany got %+v", got)
	}
	if _, ok := got["missing"]; ok {
		t.Fatal("missing key must be omitted")
	}
	if _, ok := got[""]; ok {
		t.Fatal("empty key must be omitted")
	}
}
