## Context

yaegi v0.16.1 `_select` allocates its `[]reflect.SelectCase` once per statement and each execution writes the channels from its own frame into that slice before `reflect.Select` (`knowledge/research/ext_yaegi_interp_select-cases/`). Every `lapi.Client` (one per LAPI middleware via `OwnershipKey`) runs `runStreamTicker` and `runMetricsTicker`, and every Close/Sleep runs `stopTicker`. Those three statements are shared across Clients.

## Goals / Non-Goals

**Goals:**
- Each Client's stream and metrics loop runs only on its own schedule and stops only on its own stop, for any number of Clients, under yaegi v0.16.1.
- Sleep/Close signal without waiting; Wake restarts.

**Non-Goals:**
- Changing what a poll does (single-flight, health, metrics drain).
- Other upstream review items.

## Decisions

- **`time.AfterFunc` poll timer.** `pollTimer{mu, timer, stopped}`. Start arms `time.AfterFunc(interval, fire)`. `fire` returns if stopped, runs `work()`, then `Reset(interval)` under `mu` unless stopped. `stop` sets `stopped` and calls `Timer.Stop` under `mu`; nil-safe. Reclaim already uses `AfterFunc` instead of a timer `select` for yaegi (`std_go_reclaim.md`). Prototype under yaegi: 16 loops at 1 ms, stopping half froze exactly those.
- **One helper for stream and metrics.** The distinct-body rule only kept two `select` statements apart. With no `select`, a shared helper shares no interpreter state across goroutines.
- **Fixed delay.** A poll starts one interval after the previous `work()` returned. The old ticker coalesced late ticks into one immediate extra poll; single-flight still guards overlap with the first poll and Wake.
- **`work()` stays on the timer goroutine.** No extra `go` per fire.
- **Logs.** `ticker:started` / `ticker:stopped` stay at DEBUG, emitted by start and stop.

Rejected: upstream PR 399 `for range ticker.C` (never ends after `Ticker.Stop`); duplicated `select` bodies (share is per statement); owned-channel `for range` plus a feeder goroutine (more moving parts than `AfterFunc`).

## Risks / Trade-offs

- A `fire` that passed the stopped check before `stop` runs `work()` once after Sleep/Close returned. The old loop had the same window (a tick chosen before the stop). Specs already allow an in-flight poll to finish after Close.
- Fixed delay drifts the schedule by the poll duration. Intervals are seconds to hours; drift is the poll latency.
