# LAPI stream poll

## Overview

Stream and alone modes poll `GET /v1/decisions/stream` on a ticker, on `Wake`, and optionally synchronously at `startStream`. One `lapi.Client` runs at most one poll body at a time via `streamPollMu`. Health fields (`isCrowdsecStreamHealthy`, `isCrowdsecStreamStartup`, `updateFailure`) update only inside that serialized path.

## How to use

- Entry points (`startStream` initial poll, ticker callback, `Wake`) all call `handleStreamTicker`; do not spawn concurrent stream GETs outside `streamPollMu`.
- Keep health reads (`StreamHealthy`, `streamQuery` startup flag) on fields written only under `streamPollMu`.
- On stream GET failure, delete cache key `updated` so the next poll retries LAPI instead of short-circuiting on a stale lease.
- `updateMaxFailure == 0` (default): first failed poll marks the stream unhealthy. `updateMaxFailure == -1`: failed polls never unhealth the stream.
- Lease hit on `updated` skips the stream GET only when no other poll holds `streamPollMu`; serialization prevents overlapping polls from masking failure accounting.

## Pattern snippet

```go
func (c *Client) handleStreamTicker() {
	c.streamPollMu.Lock()
	defer c.streamPollMu.Unlock()
	if err := c.handleStreamCache(); err != nil {
		// increment updateFailure; maybe flip isCrowdsecStreamHealthy
	} else {
		c.isCrowdsecStreamHealthy = true
		c.updateFailure = 0
	}
}
```

## Key files

- `pkg/lapi/client_stream.go`
- `pkg/lapi/client.go` (`streamPollMu`)
- `pkg/lapi/client_decisions.go` (`streamQuery`)

## Gotchas

- Do not use `Client.mu` for poll serialization; `Close`/`Sleep`/`Wake` already take it.
- Failed stream GET must clear the `updated` lease; otherwise Redis followers skip LAPI while health still reflects a prior failure.
- Log stream health transitions at INFO (`crowdsec stream became unhealthy|healthy`), not on every poll warn.
