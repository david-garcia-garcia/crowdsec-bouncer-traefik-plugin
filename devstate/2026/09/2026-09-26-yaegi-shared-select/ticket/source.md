# Caller spec

IssueKey: 2026-09-26-yaegi-shared-select
issueHost: local
issueRef: none

## Ask

Propose a fix, with test coverage, for the yaegi shared-select ticker bug that upstream reported and patched. The proposal must name both upstream records:

- https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/377
- https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/399

## Problem

Traefik runs this plugin under yaegi. yaegi v0.16.1 (the version Traefik 3.x bundles; still the behavior on yaegi master as described in pull request 399) builds the case list of a `select` once per statement and shares it between every goroutine that runs that statement. Stream and metrics loops both enter the same `select` inside `startTicker`. When the two tickers fire together, one loop can block on the other loop's ticker channel.

Observed upstream (issue 377): in stream mode the plugin stops calling `GET /v1/decisions/stream` for one or two metrics intervals (about 20 minutes at the default 600s metrics interval) while `POST /v1/usage-metrics` keeps running. Resumption logs the stream work twice. The other direction drops one stream tick and sends an extra metrics push. The race needs the two loops on separate CPUs. At `GOMAXPROCS=1` it is about 1000× rarer.

## What upstream changed

Pull request 399 replaced the shared `select` with a `range` over the ticker channel, which yaegi evaluates per execution. Their `stop` channel was never signalled, so `startTicker` returns the `*time.Ticker` instead. Their test `Test_runTicker_keepsEachTickerOnItsOwnChannel` fails under `yaegi test` with the old `select` and passes with the range.

## Constraint on this fork

This tree signals the ticker stop channel from Sleep and Close. Dropping that path to copy pull request 399 as-is would stop Sleep and Close from ending the loop. The fix must stay yaegi-safe and must still stop both tickers on Sleep and Close.

## Desired

A proposal (OpenSpec change) for a yaegi-safe ticker loop used by stream and metrics, which still stops when Sleep or Close signals stop, plus test coverage that shows each loop receives only its own ticks. The upstream issue and pull request are cited in the proposal.
