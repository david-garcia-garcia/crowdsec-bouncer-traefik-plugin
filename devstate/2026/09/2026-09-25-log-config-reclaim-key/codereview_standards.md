# Standards

1. [hard] Leave a trail — `pkg/captcha/zzz_owner_test.go:113` — new `TestOwnershipKey_LogConfigChangeReclaims` has no job comment; the logLevel, logFilePath, and logFormat forks are three blocks with no intros
   Fix: Add a job comment that names the three knobs, and a one-line intro on each fork that says that knob-only Config change must change OwnershipKey
   Status: done
   Argument: Job comment and per-knob block intros on TestOwnershipKey_LogConfigChangeReclaims (72bec78).
   Quote:
      ```
      func TestOwnershipKey_LogConfigChangeReclaims(t *testing.T) {
      	left := testOwnerConfig(t, 10)
      	rightLevel := *left
      	rightLevel.LogLevel = "DEBUG"
      	if OwnershipKey(left, "mw") == OwnershipKey(&rightLevel, "mw") {
      		t.Fatal("logLevel change must change the ownership key")
      	}
      	rightPath := *left
      	rightPath.LogFilePath = "/tmp/bouncer.log"
      	if OwnershipKey(left, "mw") == OwnershipKey(&rightPath, "mw") {
      		t.Fatal("logFilePath change must change the ownership key")
      	}
      	rightFormat := *left
      	rightFormat.LogFormat = "json"
      	if OwnershipKey(left, "mw") == OwnershipKey(&rightFormat, "mw") {
      		t.Fatal("logFormat change must change the ownership key")
      	}
      }
      ```
