// Package cache implements utility routines for manipulating cache.
// It supports currently local file and redis cache.
package cache

import (
	"testing"

	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
	simpleredis "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/simpleredis"
)

func Test_Get(t *testing.T) {
	IPInCache := "10.0.0.10"
	IPNotInCache := "10.0.0.20"
	client := &Client{cache: &localCache{}, log: logger.New("INFO", "")}
	client.Set(IPInCache, BannedValue, 10)
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
		{name: "Fetch Known valid IP", args: args{clientIP: IPInCache}, want: BannedValue, wantErr: false, valueErr: ""},
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
		{name: "Set valid IP in local cache for 0 sec", args: args{clientIP: IPInCache, value: BannedValue, duration: 0}, want: "", wantErr: true, valueErr: CacheMiss},
		{name: "Set valid IP in local cache for 10 sec", args: args{clientIP: IPInCache, value: BannedValue, duration: 10}, want: BannedValue, wantErr: false, valueErr: ""},
		{name: "Set valid IP in local cache for 10 sec", args: args{clientIP: IPInCache, value: NoBannedValue, duration: 10}, want: NoBannedValue, wantErr: false, valueErr: ""},
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
	client.Set(IPInCache, BannedValue, 10)
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

// indexOfReader returns the position of r inside rc.readers, or -1 when r is the writer (the no-readers fallback).
func indexOfReader(rc *redisCache, r *simpleredis.SimpleRedis) int {
	if r == rc.writer {
		return -1
	}
	for i := range rc.readers {
		if r == rc.readers[i] {
			return i
		}
	}
	return -2
}

func Test_nextReader(t *testing.T) {
	// The counter starts at 0, so the first Add(1) yields index 1, then 2, 0, 1, ... over n readers.
	tests := []struct {
		name    string
		readers int
		want    []int
	}{
		{name: "round-robin over three readers", readers: 3, want: []int{1, 2, 0, 1, 2, 0, 1}},
		{name: "single reader always selected", readers: 1, want: []int{0, 0, 0, 0, 0}},
		{name: "no readers fall back to writer", readers: 0, want: []int{-1, -1, -1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := &redisCache{log: logger.New("INFO", "")}
			rc.writer = &simpleredis.SimpleRedis{}
			rc.readers = make([]*simpleredis.SimpleRedis, tt.readers)
			for i := range rc.readers {
				rc.readers[i] = &simpleredis.SimpleRedis{}
			}
			for call, want := range tt.want {
				if got := indexOfReader(rc, rc.nextReader()); got != want {
					t.Errorf("call %d: nextReader() -> reader[%d], want reader[%d]", call, got, want)
				}
			}
		})
	}
}

func Test_memoryClientsDoNotShare(t *testing.T) {
	a := &Client{}
	b := &Client{}
	a.New(logger.New("INFO", ""), false, "", nil, "", "", "")
	b.New(logger.New("INFO", ""), false, "", nil, "", "", "")
	a.Set("1.2.3.4", BannedValue, 10)
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

func Test_ClientCloseRedis(t *testing.T) {
	client := &Client{}
	client.New(logger.New("INFO", ""), true, "127.0.0.1:1", []string{"127.0.0.1:1"}, "", "", "p")
	client.Close()
	client.Close()
	var empty *Client
	empty.Close()
}

func Test_prefixed(t *testing.T) {
	if got := prefixed("", "ip"); got != "ip" {
		t.Fatalf("empty prefix: got %q", got)
	}
	if got := prefixed("ab", "ip"); got != "ab:ip" {
		t.Fatalf("prefix: got %q", got)
	}
	if got := prefixed("a", "updated"); got != "a:updated" {
		t.Fatalf("lease key: got %q", got)
	}
}

func Test_redisCacheUsesPrefix(t *testing.T) {
	rc := &redisCache{prefix: "conn1"}
	if got := prefixed(rc.prefix, "1.2.3.4"); got != "conn1:1.2.3.4" {
		t.Fatalf("got %q", got)
	}
}
