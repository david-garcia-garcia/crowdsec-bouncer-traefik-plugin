# Dead

1. [hard] Test-only new symbol — `pkg/decisionstore/store.go:157` — `(*Store).StreamPollInFlight` has no production caller
   ```
   // StreamPollInFlight is non-zero while a stream GET+apply owns this session.
   func (s *Store) StreamPollInFlight() int64 {
   	return atomic.LoadInt64(&s.streamPollInFlight)
   }
   ```
   Grep `StreamPollInFlight` on `*.go`: definition plus `pkg/decisionstore/zzz_lifecycle_log_test.go` (`TestStore_StreamPollCAS`) and `pkg/lapi/zzz_session_test.go` (`TestOpenStream_NewClientKeepsStoreStreamFlags`). Production already enters/releases via `TryBeginStreamPoll` / `EndStreamPoll` (`pkg/lapi/client_stream.go`).
   → Delete `StreamPollInFlight`; assert hold/release via `TryBeginStreamPoll` skip then reenter after `EndStreamPoll`, and New-must-not-zero via `handleStreamTicker` skip
# Dead

1. [hard] Test-only new symbol — `pkg/decisionstore/store.go:157` — `(*Store).StreamPollInFlight` has no production caller
   ```
   // StreamPollInFlight is non-zero while a stream GET+apply owns this session.
   func (s *Store) StreamPollInFlight() int64 {
   	return atomic.LoadInt64(&s.streamPollInFlight)
   }
   ```
   Grep `StreamPollInFlight` on `*.go`: definition plus `pkg/decisionstore/zzz_lifecycle_log_test.go` (`TestStore_StreamPollCAS`) and `pkg/lapi/zzz_session_test.go` (`TestOpenStream_NewClientKeepsStoreStreamFlags`). Production already enters/releases via `TryBeginStreamPoll` / `EndStreamPoll` (`pkg/lapi/client_stream.go`).
   → Delete `StreamPollInFlight`; assert hold/release via `TryBeginStreamPoll` skip then reenter after `EndStreamPoll`, and New-must-not-zero via `handleStreamTicker` skip
   Status: done
   Argument: deleted the getter; CAS tests use TryBeginStreamPoll skip/reenter; NewClient holds via TryBeginStreamPoll then asserts a second enter fails.

