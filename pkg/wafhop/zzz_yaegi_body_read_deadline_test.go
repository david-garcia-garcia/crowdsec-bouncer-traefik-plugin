package wafhop

import (
	"fmt"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/yaegitest"
)

// TestYaegi_ReadBodyDeadlineCutsStalledBody runs the body read deadline (time.AfterFunc,
// http.NewResponseController, Timer.Stop) under yaegi v0.16.1, the interpreter Traefik loads this
// plugin with: a real HTTP/1.1 chunked body that never ends, cut through the response controller,
// and a stalled body with no controller, cut by the Close fallback.
func TestYaegi_ReadBodyDeadlineCutsStalledBody(t *testing.T) {
	yaegitest.Run(t, yaegitest.GoPath(t), fmt.Sprintf(yaegiReadBodyDeadlineProgram, yaegitest.ModulePath+"/pkg/wafhop"))
}

// yaegiReadBodyDeadlineProgram is the package main program TestYaegi_ReadBodyDeadlineCutsStalledBody
// interprets. The %q verb is the wafhop import path; %% escapes the program's own verbs.
const yaegiReadBodyDeadlineProgram = `package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	wafhop %q
)

type outcome struct {
	err     error
	elapsed time.Duration
}

type stalledBody struct {
	cut chan struct{}
}

func (s *stalledBody) Read(p []byte) (int, error) {
	<-s.cut
	return 0, errors.New("body closed")
}

func (s *stalledBody) Close() error {
	close(s.cut)
	return nil
}

func exitWithFailure(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

// serveStalledBody sends a chunked body that never ends and returns what the last leg's ReadBody saw.
// With two legs the first stops at a 4-byte limit, so the second reads the rest through the
// first leg's buffered body.
func serveStalledBody(legs int) (error, time.Duration) {
	outcomes := make(chan outcome, 1)
	front := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		started := time.Now()
		ctrl := http.NewResponseController(rw)
		if legs == 2 {
			if _, err := wafhop.ReadBody(r, 4, wafhop.TruncateAtLimit, ctrl, time.Second); err != nil {
				outcomes <- outcome{err: err, elapsed: time.Since(started)}
				return
			}
		}
		_, err := wafhop.ReadBody(r, 1<<20, wafhop.RejectOverLimit, ctrl, time.Second)
		outcomes <- outcome{err: err, elapsed: time.Since(started)}
		rw.WriteHeader(http.StatusBadRequest)
	}))
	defer front.Close()
	bodyReader, bodyWriter := io.Pipe()
	defer func() { _ = bodyWriter.Close() }()
	go func() { _, _ = bodyWriter.Write([]byte("partial")) }()
	go func() {
		res, doErr := http.Post(front.URL+"/stream", "application/octet-stream", bodyReader)
		if doErr == nil {
			_ = res.Body.Close()
		}
	}()
	got := <-outcomes
	return got.err, got.elapsed
}

func main() {
	// Hard stop: a deadline that never fires would otherwise hang the interpreter.
	time.AfterFunc(20*time.Second, func() { exitWithFailure("body read deadline did not fire within 20s") })

	// HTTP/1.1 chunked body cut through http.NewResponseController: one leg, then a second leg
	// that reads the stalled rest after the first leg stopped at its limit.
	for _, legs := range []int{1, 2} {
		err, elapsed := serveStalledBody(legs)
		if !errors.Is(err, wafhop.ErrBodyReadTimeout) {
			exitWithFailure("HTTP/1.1 %%d leg(s): ReadBody error %%v, want ErrBodyReadTimeout", legs, err)
		}
		if elapsed > 5*time.Second {
			exitWithFailure("HTTP/1.1 %%d leg(s): ReadBody returned after %%v, want about 1s", legs, elapsed)
		}
	}

	// No controller: the deadline closes the body.
	req, _ := http.NewRequest(http.MethodPost, "http://example.com/", nil)
	req.ContentLength = -1
	req.Body = &stalledBody{cut: make(chan struct{})}
	_, err := wafhop.ReadBody(req, 100, wafhop.RejectOverLimit, nil, 200*time.Millisecond)
	if !errors.Is(err, wafhop.ErrBodyReadTimeout) {
		exitWithFailure("nil controller ReadBody error %%v, want ErrBodyReadTimeout", err)
	}
}
`
