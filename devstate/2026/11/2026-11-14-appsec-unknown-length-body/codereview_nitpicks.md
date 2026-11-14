# Nitpicks

1. [hard] Name for the scope — `pkg/appsec/query.go:266` — `readClientBodyForAppsec` drops a clause its caller relies on: besides reading a capped copy for AppSec it replaces `req.Body` with the replay for origin (`req.Body = io.NopCloser(io.MultiReader(&bodyBuffer, clientBody))`); only the doc comment says so, the identifier reads as a pure read
   Quote:
   ```go
   func (c *Client) readClientBodyForAppsec(req clientrequest.Request, responseController *http.ResponseController) ([]byte, error) {
   	clientBody := req.Body
   	...
   	// Give origin the bytes already read followed by whatever the client still sends past the limit.
   	req.Body = io.NopCloser(io.MultiReader(&bodyBuffer, clientBody))
   	return bodyBytes, nil
   }
   ```
   Fix: Spell the whole job, e.g. `copyClientBodyForAppsecAndRestoreForOrigin` (rename the one call in `newAppsecBodyRequest`)
   Status: done
   Argument: Renamed to `copyClientBodyForAppsecAndRestoreForOrigin` (one call site); design.md, tasks.md 3.3 and the debt note updated.
2. [hard] Clear conditions — `pkg/appsec/query.go:286` — `deadlineTimer != nil && !deadlineTimer.Stop()` is the question "did the body-read deadline fire", but the reader must know that nil means "not armed (declared length)" and that a false `Stop()` means "already fired"; the condition also stops the timer as a side effect
   Quote:
   ```go
   if deadlineTimer != nil && !deadlineTimer.Stop() {
   	logger.Debounced(c.log, slog.LevelWarn, 5*time.Second, msgBodyReadTimeout, ...)
   	return nil, ErrBodyReadTimeout
   }
   ```
   Fix: Ask a predicate named for the case, e.g. `if bodyReadDeadlineFired(deadlineTimer) {` with `func bodyReadDeadlineFired(timer *time.Timer) bool { if timer == nil { return false }; return !timer.Stop() }` (same truth table, comment says it stops the timer)
   Status: done
   Argument: Added `bodyReadDeadlineFired(deadlineTimer)` (nil → false, else `!Stop()`); the caller asks it.
3. [hard] Linear coding — `pkg/appsec/query.go:270` — arming the body-read deadline (unknown-length gate, `time.AfterFunc`, and the cut choice "controller deadline, else `Close` when the controller is nil or `SetReadDeadline` errors") is a second self-contained job inlined ahead of the capped read; the reader re-derives the cut fallback from a compound condition with a side-effecting call inside the closure
   Quote:
   ```go
   var deadlineTimer *time.Timer
   if isBodyLengthUnknown(req.Request) {
   	deadlineTimer = time.AfterFunc(time.Duration(c.bodyReadTimeoutSeconds)*time.Second, func() {
   		// Cut the in-flight read. The controller reaches HTTP/1.1 and HTTP/2; Close only HTTP/2 (and HTTP/3).
   		if responseController == nil || responseController.SetReadDeadline(time.Now()) != nil {
   			_ = clientBody.Close()
   		}
   	})
   }
   ```
   Fix: Extract `func (c *Client) armBodyReadDeadline(req clientrequest.Request, clientBody io.Closer, responseController *http.ResponseController) *time.Timer` (early `return nil` for a declared length) and a `cutClientBodyRead(clientBody, responseController)` for the closure body with guard clauses (`if responseController != nil && responseController.SetReadDeadline(time.Now()) == nil { return }`, then `Close`); the outer unit asks `deadlineTimer := c.armBodyReadDeadline(...)`. Plain functions and a closure only, so Yaegi v0.16.1 is unaffected
   Status: done
   Argument: Extracted `(*Client).armBodyReadDeadline` (early nil for a declared length) and `cutClientBodyRead` (controller deadline, else `Close`) in `pkg/appsec/query.go`.
4. [hard] Linear coding — `pkg/appsec/query.go:250` — the guard re-lists three clauses that are one concept ("this request has no body AppSec inspects") as a mix of `==` and a negated method predicate; the diff rewrote this condition from the old `switch` case
   Quote:
   ```go
   if req.Body == nil || req.Body == http.NoBody || !isMethodWithForwardableBody(req.Method) {
   	appsecReq, _ := http.NewRequest(http.MethodGet, target, nil)
   	return appsecReq, nil
   }
   ```
   Fix: Name the concept next to `isMethodWithForwardableBody`, e.g. `func hasBodyForAppsec(httpReq *http.Request) bool` with guard clauses (`nil` / `http.NoBody` → false, then `isMethodWithForwardableBody(httpReq.Method)`); the caller asks `if !hasBodyForAppsec(req.Request) {` (same membership)
   Status: done
   Argument: Added `hasBodyForAppsec(httpReq)` next to `isMethodWithForwardableBody`; `newAppsecBodyRequest` asks `!hasBodyForAppsec(req.Request)`.
