## 1. Serialize stream polls

- [ ] 1.1 Add `streamPollMu` on `Client` and TryLock at the start of `handleStreamTicker`; unlock after `handleStreamCache`; failed TryLock returns without touching health or `updateFailure`
- [ ] 1.2 Keep `startTicker` `go work()` and the `Wake` extra poll
- [ ] 1.3 Test: overlapping `handleStreamTicker`/`Wake` while a stream GET is held yields one in-flight GET; extras do not reset `updateFailure`

## 2. Bound LAPI HTTP

- [ ] 2.1 `crowdsecQuery` uses a request context deadline from `HTTPTimeoutSeconds` and does not read status/body when `Do` returns an error
- [ ] 2.2 Test: hung LAPI (no headers) returns an error within `HTTPTimeoutSeconds` plus slack, without panic

## 3. Usage

- [ ] 3.1 Gotcha on `knowledge/devdocs/core_plugin_middleware.md`: one in-flight stream poll per Client; TryLock skip is not healthy
