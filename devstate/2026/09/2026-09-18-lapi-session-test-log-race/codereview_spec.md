# Spec

none.

Both requirements of `std_go_test_log-sink` are satisfied by the apply: the mutex-guarded sink (`pkg/lapi/zzz_logsink_test.go`) with all four capture sites converted, and `Close()` before the log read in the two tests that open a real client. Nothing in the diff is outside the proposal: no production file, no CI file, no assertion removed.
