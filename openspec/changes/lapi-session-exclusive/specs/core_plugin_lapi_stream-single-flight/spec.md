## ADDED Requirements

### Requirement: A new Client reads store streamReady before the first GET
`lapi.New` SHALL load DecisionStore `streamReady` (`int64`, `atomic.LoadInt64`) before the first stream GET. When that value is non-zero, `isCrowdsecStreamStartup` SHALL start at 0 so the first poll does not send `startup=true`. When it is zero (new empty store, including a mode change that produced a new `SessionHex`), `isCrowdsecStreamStartup` SHALL start at 1. Intra-Client skip-if-busy on `handleStreamTicker` SHALL stay the overlap guard on one Client. Live/none MUST NOT use this flag. Implementations MUST NOT use `atomic.Bool` or `atomic.Int64` as a struct field.

#### Scenario: New Client on a warm store skips startup true
- **WHEN** a DecisionStore already has `streamReady` set from a finished stream poll
- **AND** a new Client is constructed against that store
- **THEN** the Client’s first stream GET uses `startup=false`

#### Scenario: Mode change empty store starts at startup true
- **WHEN** mode change produces a new `SessionHex` and an empty DecisionStore
- **AND** a new stream Client is constructed against that store
- **THEN** the first stream GET uses `startup=true`
