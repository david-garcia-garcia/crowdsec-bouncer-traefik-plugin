# Requirement
IssueKey: 2026-10-13-challenge-drop-once

# Count a bot-detection challenge once

`handleAppsecResponseServeHTTP` calls `recordDropped` for every relayed AppSec envelope. A visitor who solves a challenge therefore increments dropped for the page, `fpscanner.js`, `pow-worker.js`, and `/crowdsec-internal/challenge/submit`, including a successful submit. A throwaway test on this tree: the page counted 1, then the submit path counted +1 (`TestDroppedCount` origin `appsec`, remediation empty).

The bot-detection spec currently says `blockedRequests` SHALL increment on relay. Update that so a relay whose path is under `/crowdsec-internal/challenge/` does not increment dropped (request or bytes). The challenge page (any other path) still increments once. Bans, captcha remediation via pkg/captcha, and non-challenge relays stay counted as today.

Do not add origin or remediation labels. Do not change the metrics POST shape.

Regression test: a challenge envelope on `/protected` increments dropped by 1; the same envelope on `/crowdsec-internal/challenge/submit` does not. Run the tests on this machine.

Upstream (must appear on every delivery card / PR body): https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 (fixes https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/402, point 5). Say this fork's gap versus that PR. Do not claim we copied their patch.

## Current (code)

- `bouncer.go` `handleAppsecResponseServeHTTP`: not found on `origin/main` (HEAD `23ce76d3`). That function exists on `upstream/main` after maxlerebourg/crowdsec-bouncer-traefik-plugin#343 and on this fork's `origin/master` at `pkg/bouncer/bouncer.go`.
- `bouncer.go` `recordDropped`: not found. Dest counts with a process-wide `blockedRequests` `int64`.
- `bouncer.go` `handleBanServeHTTP` (line 446): `atomic.AddInt64(&blockedRequests, 1)` on every ban, including AppSec non-200 from `handleNextServeHTTP`.
- `bouncer.go` `handleRemediationServeHTTP` (line 483): `atomic.AddInt64(&blockedRequests, 1)` when serving a captcha page via `pkg/captcha`.
- `bouncer.go` `appsecQuery` (line 756): HTTP 200 returns nil (request proceeds to `next`). HTTP 500 follows `appsecFailureBlock`. Other non-200 returns `appsecQuery statusCode:<n>`, which `handleNextServeHTTP` turns into a ban. The AppSec body is drained, not parsed; there is no JSON `action` / `user_body_content` relay.
- `bouncer.go` `reportMetrics` (line 827): POST `dropped` with labels `{type: traefik_plugin}` only. No origin, no remediation, no bytes series.
- `TestDroppedCount`: not found. Dest has no origin/remediation window API.
- `openspec/specs/core_plugin_appsec_bot-detection/spec.md`: not found on dest. Dest has no `openspec/` tree.
- Path `/crowdsec-internal/challenge/`: not found as a special prefix on dest. README on dest does not mention bot-detection callbacks.

## Desired

- A relayed AppSec challenge envelope on a path other than `/crowdsec-internal/challenge/*` increments dropped by 1 (request; bytes if dest grows a bytes series — dest has none today).
- The same envelope on a path under `/crowdsec-internal/challenge/` (scripts, submit, including a successful submit) does not increment dropped (request or bytes).
- Bans, captcha pages from `pkg/captcha`, and non-challenge remediations stay counted as today.
- Do not add origin or remediation labels. Do not change the metrics POST shape.
- Regression: challenge envelope on `/protected` increments dropped by 1; the same envelope on `/crowdsec-internal/challenge/submit` does not.
- Delivery card and PR body name upstream https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 (fixes https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/402, point 5) and this fork's gap versus that PR. Do not claim we copied their patch.

## Affected

- `bouncer.go` (the increment at the AppSec challenge-relay site, once that site exists)
- A regression test next to the existing AppSec tests in `bouncer_test.go`

## Out of scope

- Adding origin or remediation labels on the metrics POST.
- Changing the metrics POST shape.
- Merging upstream #343 (bot-detection relay) as a drive-by, unless this run cannot otherwise attach the skip.
- Copying upstream PR 403's patch.
- Bans, captcha via `pkg/captcha`, and non-challenge remediations.

## Unknowns

- Whether dest will grow a structured AppSec JSON relay in this change or already has one after a dest sync this run is not allowed to redo.
- What exact bytes series dest would skip: dest has no `IncDroppedBytes`; upstream PR 403 point 5 only skips the request counter.
- Whether AppSec returns HTTP 200 or 403 for challenge assets on dest's unparsed `appsecQuery` path (those currently pass or ban, they do not relay).
- The throwaway `TestDroppedCount` result named in the dump was not re-run on this dest HEAD.

## Tensions

- Ticket vs dest: the dump names `handleAppsecResponseServeHTTP`, `recordDropped`, `TestDroppedCount` origin `appsec` / remediation empty, and `openspec/specs/core_plugin_appsec_bot-detection`. None of those exist on `origin/main`. They exist on this fork's `origin/master` and (for the relay function) on `upstream/main` after #343.
- Ticket vs dest metrics: the dump asks to skip dropped bytes; dest posts only a request `dropped` item.
- Ticket vs protocol: counting "a challenge envelope" assumes the bouncer writes AppSec `user_body_content` to the client. Dest never parses that JSON.
- Upstream PR 403 point 5 patches `handleAppsecResponseServeHTTP` to skip `blockedRequests` when `isAppsecChallengePath(req.URL.Path)`. This fork's `main` has not merged #343, so that function is absent; the over-count the ticket describes cannot fire on dest until a relay exists.
