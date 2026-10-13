# Dead

1. [hard] Leftover production path — `pkg/ip/checker.go:47` — `(ip *Checker) Contains` has no production callers after parse-once wiring moved `getIP` and `ServeHTTP` to `ContainsIP`

```go
// Contains checks if provided address is in the trusted IPs.
func (ip *Checker) Contains(addr string) (bool, error) {
	if len(addr) == 0 {
		return false, errors.New("Contains:noAddress")
	}

	ipAddr, err := parseIP(addr)
	if err != nil {
		return false, fmt.Errorf("Contains:parseAddress addr:%s %w", addr, err)
	}

	return ip.ContainsIP(ipAddr), nil
}
```

Grep `Checker\.Contains` and `checker\.Contains` across `**/*.go` (excluding `*_test.go`, `tests/`, docs): no production hits. Only `pkg/ip/checker_test.go` calls it. `getIP` now uses `ContainsIP` (`checker.go:122`); `ServeHTTP` uses `ContainsIP` (`bouncer.go:140`).

→ Delete `Contains`; retarget `checker_test.go` to `parseIP` then `ContainsIP` (or test through `GetRemoteIP` / hop walk).

Status: skipped
Argument: judgement — Contains remains the string public API (tests, usage packet, prior radix-lookup spec). ServeHTTP uses ContainsIP; deleting Contains is outside the parse-once job.
