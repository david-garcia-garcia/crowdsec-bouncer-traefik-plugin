package lapi

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPrepare_DisabledRedisSkipsPasswordFile is leftover RedisCachePasswordFile must not load or hash into StoreKey while Redis is off.
func TestPrepare_DisabledRedisSkipsPasswordFile(t *testing.T) {
	passwordFile := filepath.Join(t.TempDir(), "redis-password")
	if err := os.WriteFile(passwordFile, []byte("stale-secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	staleFileDisabled := testStreamConfig("lapi.example:8080", 1)
	staleFileDisabled.RedisCacheEnabled = false
	staleFileDisabled.RedisCachePassword = ""
	staleFileDisabled.RedisCachePasswordFile = passwordFile
	if err := Prepare(staleFileDisabled, nil); err != nil {
		t.Fatal(err)
	}
	if staleFileDisabled.RedisCachePassword != "" {
		t.Fatalf("disabled Redis must not load RedisCachePasswordFile, got %q", staleFileDisabled.RedisCachePassword)
	}

	emptyPasswordDisabled := testStreamConfig("lapi.example:8080", 1)
	emptyPasswordDisabled.RedisCacheEnabled = false
	emptyPasswordDisabled.RedisCachePassword = ""
	emptyPasswordDisabled.RedisCachePasswordFile = ""
	if StoreKey(staleFileDisabled) != StoreKey(emptyPasswordDisabled) {
		t.Fatal("disabled Redis leftover password file must not change StoreKey")
	}
}

// TestPrepare_EnabledRedisLoadsPasswordFile is Redis on must still resolve RedisCachePasswordFile.
func TestPrepare_EnabledRedisLoadsPasswordFile(t *testing.T) {
	passwordFile := filepath.Join(t.TempDir(), "redis-password")
	if err := os.WriteFile(passwordFile, []byte("stale-secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	staleFileEnabled := testStreamConfig("lapi.example:8080", 1)
	staleFileEnabled.RedisCacheEnabled = true
	staleFileEnabled.RedisCachePassword = ""
	staleFileEnabled.RedisCachePasswordFile = passwordFile
	if err := Prepare(staleFileEnabled, nil); err != nil {
		t.Fatal(err)
	}
	if staleFileEnabled.RedisCachePassword != "stale-secret" {
		t.Fatalf("enabled Redis must load RedisCachePasswordFile, got %q", staleFileEnabled.RedisCachePassword)
	}
}
