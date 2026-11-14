# Standards

1. [hard] One job, one owner — `pkg/lapi/client.go:308` — new `pollTimer` type (with `startPollTimer`, `startPollTimerEvery`, `fire`, `isStopped`, `stop`) is a distinct live unit added to the `Client` file; the type's file must be named for the type
   Quote:
   ```
      // pollTimer runs one Client loop (stream or usage-metrics) on a stdlib timer until stop.
      type pollTimer struct {
      	mu      sync.Mutex
      	timer   *time.Timer
      	stopped bool
      	name    string
      	log     *slog.Logger
      }
   ```
   Fix: Move `pollTimer` and its constructors/methods (`client.go:304-367`) into `pkg/lapi/poll_timer.go`, matching `zzz_poll_timer_test.go`
   Status: done
   Argument: Moved `pollTimer` and its functions to `pkg/lapi/poll_timer.go`; `client.go` keeps only the Client wiring.
2. [hard] Leave a trail — `pkg/lapi/client.go:347` — new method `isStopped` has no job comment
   Quote:
   ```
      func (p *pollTimer) isStopped() bool {
      	p.mu.Lock()
      	defer p.mu.Unlock()
      	return p.stopped
      }
   ```
   Fix: Add a one-line comment, e.g. `// isStopped reports under mu whether stop has ended this loop.`
   Status: done
   Argument: Added the job comment on `isStopped` in `pkg/lapi/poll_timer.go`.
3. [hard] Leave a trail — `pkg/lapi/zzz_poll_timer_test.go:49` — new helper `discardLogger` has no job comment
   Quote:
   ```
      func discardLogger() *slog.Logger {
      	return slog.New(slog.NewTextHandler(io.Discard, nil))
      }
   ```
   Fix: Add a one-line comment saying it returns a logger that drops all output for poll-timer tests
   Status: done
   Argument: Helper removed; tests call `discardLoggerForTest` in `pkg/lapi/test_client.go`, which has a job comment.
4. [judgement] Duplicated Code — `pkg/lapi/test_client.go:100` — `StartPollTimerForTest` rebuilds the same discard logger that `discardLogger` (`zzz_poll_timer_test.go:50`) builds in the same change
   Quote:
   ```
      poll := startPollTimerEvery("test", interval, slog.New(slog.NewTextHandler(io.Discard, nil)), work)
   ```
   Fix: Define the discard-logger helper once in `test_client.go` (test-named, e.g. `discardLoggerForTest`) and call it from both `StartPollTimerForTest` and `zzz_poll_timer_test.go`
   Status: done
   Argument: `discardLoggerForTest` is defined once in `pkg/lapi/test_client.go` and used by `StartPollTimerForTest` and the poll-timer tests.
