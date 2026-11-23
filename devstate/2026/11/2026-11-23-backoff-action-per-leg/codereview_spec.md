# Spec

1. [judgement] Stream poll gate test — `openspec/changes/add-backoff-action-and-lapi-live-gate/tasks.md:37` — task 2.4 (checked) lists "stream polling against a 503 server never touches a gate" as a verify test for `specs/core_plugin_lapi_admission-gate/spec.md:95` ("Stream, alone, CAPI login, and the alone token renewal MUST NOT record on any gate"); no such test is in the diff. The SHALL holds by construction (stream/alone build a nil gate, proven only at construction by `pkg/lapi/zzz_live_gate_test.go:107` `TestNew_liveGatePerMode`, and `Record` is only called from `queryLiveDecisions`)
   Fix: Add a `pkg/lapi` test that polls a stream Client against a 503 server past `admission.TripFailures` and asserts no gate exists and every poll still reaches the server, or drop that verify line from task 2.4
   Status: done
   Argument: Added `TestHandleStreamCache_failingPollsNeverGate` in `pkg/lapi/zzz_live_gate_test.go`: 20 stream polls against a 503 LAPI each reach LAPI and fail as themselves, and the stream Client has no gate.
