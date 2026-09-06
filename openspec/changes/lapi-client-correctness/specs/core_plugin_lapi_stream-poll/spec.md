## Purpose

Governs serialized stream/alone polling on one `lapi.Client`: one in-flight poll, consistent stream health fields, and lease behavior that does not mask an failing poll.

## ADDED Requirements

### Requirement: At most one in-flight stream poll per Client
The plugin SHALL run at most one stream poll body (initial poll, ticker tick, or Wake-triggered poll) at a time per `lapi.Client`. Overlapping entry points (`startStream`, `startTicker`, `Wake`) MUST NOT execute concurrent stream GETs or concurrent health mutations for that client.

#### Scenario: Ticker does not overlap prior poll
- **WHEN** a stream poll is still running and the update ticker fires again
- **THEN** the second poll waits or is skipped until the first completes
- **AND** only one stream GET is in flight

#### Scenario: Wake does not overlap ticker poll
- **WHEN** `Wake` is called while a ticker-driven poll is in flight
- **THEN** the Wake-triggered poll does not run concurrently with the in-flight poll

### Requirement: Stream health fields are consistent under poll serialization
Reads of stream health state (`StreamHealthy`, startup flag for `startup=` on stream GET, failure counter toward `UpdateMaxFailure`) SHALL observe values produced only by the serialized poll path. Concurrent unsynchronized read/write of those fields MUST NOT occur.

#### Scenario: streamQuery sees stable startup flag
- **WHEN** `streamQuery` builds the stream URL while a poll is updating health fields
- **THEN** it reads startup and healthy flags without racing unsynchronized writers

#### Scenario: UpdateMaxFailure threshold on failed poll
- **WHEN** `updateMaxFailure` is `0` and a serialized poll fails to fetch or apply stream decisions
- **THEN** the stream becomes unhealthy on that failure
- **AND** a later successful poll restores healthy

#### Scenario: UpdateMaxFailure minus one never unhealthies
- **WHEN** `updateMaxFailure` is `-1` and stream polls fail
- **THEN** the stream stays healthy regardless of poll failures

### Requirement: Lease short-circuit respects in-flight poll outcome
When the stream cache lease on key `updated` is held, the poll MAY skip the stream GET only if no other stream poll is in flight for that client. A lease hit MUST NOT return success that resets or hides failure accounting while another poll is failing.

#### Scenario: Lease hit with no in-flight poll
- **WHEN** the `updated` lease is held and no stream poll is in flight
- **THEN** the poll MAY return without issuing a stream GET

#### Scenario: Lease hit during failing in-flight poll
- **WHEN** the `updated` lease is held and another stream poll is in flight and failing
- **THEN** the lease short-circuit MUST NOT report success that clears or masks the in-flight failure outcome
