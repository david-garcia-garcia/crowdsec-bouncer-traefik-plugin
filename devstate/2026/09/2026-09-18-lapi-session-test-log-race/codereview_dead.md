# Dead

none.

`syncLogSink`, its two methods, and `newTestLogSink` all have in-package callers (`zzz_session_test.go` three sites, `zzz_client_stream_log_test.go` one). Nothing is left behind: the `bytes` import is gone from both converted files, and no helper was orphaned by the conversion.
