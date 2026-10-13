package lapi

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPrepare_DisabledRedisSkipsPasswordFile is leftover LapiRedisPasswordFile must not load or hash into StoreKey while Redis is off.
func TestPrepare_DisabledRedisSkipsPasswordFile(t *testing.T) {
	passwordFile := filepath.Join(t.TempDir(), "redis-password")
	if err := os.WriteFile(passwordFile, []byte("stale-secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	staleFileDisabled := testStreamConfig("lapi.example:8080", 1)
	staleFileDisabled.LapiRedisEnabled = false
	staleFileDisabled.LapiRedisPassword = ""
	staleFileDisabled.LapiRedisPasswordFile = passwordFile
	if err := Prepare(staleFileDisabled, nil, ""); err != nil {
		t.Fatal(err)
	}
	if staleFileDisabled.LapiRedisPassword != "" {
		t.Fatalf("disabled Redis must not load LapiRedisPasswordFile, got %q", staleFileDisabled.LapiRedisPassword)
	}

	emptyPasswordDisabled := testStreamConfig("lapi.example:8080", 1)
	emptyPasswordDisabled.LapiRedisEnabled = false
	emptyPasswordDisabled.LapiRedisPassword = ""
	emptyPasswordDisabled.LapiRedisPasswordFile = ""
	if StoreKey(staleFileDisabled) != StoreKey(emptyPasswordDisabled) {
		t.Fatal("disabled Redis leftover password file must not change StoreKey")
	}
}

// TestPrepare_EnabledRedisLoadsPasswordFile is Redis on must still resolve LapiRedisPasswordFile.
func TestPrepare_EnabledRedisLoadsPasswordFile(t *testing.T) {
	passwordFile := filepath.Join(t.TempDir(), "redis-password")
	if err := os.WriteFile(passwordFile, []byte("stale-secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	staleFileEnabled := testStreamConfig("lapi.example:8080", 1)
	staleFileEnabled.LapiRedisEnabled = true
	staleFileEnabled.LapiRedisPassword = ""
	staleFileEnabled.LapiRedisPasswordFile = passwordFile
	if err := Prepare(staleFileEnabled, nil, ""); err != nil {
		t.Fatal(err)
	}
	if staleFileEnabled.LapiRedisPassword != "stale-secret" {
		t.Fatalf("enabled Redis must load LapiRedisPasswordFile, got %q", staleFileEnabled.LapiRedisPassword)
	}
}
