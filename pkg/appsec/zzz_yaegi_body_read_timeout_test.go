package appsec

import (
	"fmt"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/yaegitest"
)

// TestYaegi_bodyReadTimeout_cutsStalledBody runs the body-read deadline (time.AfterFunc,
// http.NewResponseController, Timer.Stop) under yaegi v0.16.1, the interpreter Traefik loads
// this plugin with, against a real HTTP/1.1 server whose client never ends its chunked body.
func TestYaegi_bodyReadTimeout_cutsStalledBody(t *testing.T) {
	yaegitest.Run(t, yaegitest.GoPath(t), bodyReadTimeoutYaegiSource())
}

// bodyReadTimeoutYaegiSource is a package main that serves one stalled request through appsec.Client.Query.
func bodyReadTimeoutYaegiSource() string {
	return fmt.Sprintf(`package main

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	appsec %q
	clientrequest %q
	configuration %q
)

type outcome struct {
	err     error
	elapsed time.Duration
}

func main() {
	// Hard stop: a deadline that never fires would otherwise hang the interpreter.
	time.AfterFunc(20*time.Second, func() {
		fmt.Fprintln(os.Stderr, "body read deadline did not fire within 20s")
		os.Exit(1)
	})

	cfg := configuration.New()
	cfg.AppsecEnabled = true
	cfg.AppsecScheme = "http"
	cfg.AppsecHost = "127.0.0.1:1"
	cfg.AppsecBodyReadTimeoutSeconds = 1
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	client, err := appsec.New(cfg, log, "yaegi", "yaegi", "yaegi")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	outcomes := make(chan outcome, 1)
	front := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		started := time.Now()
		req := clientrequest.New(r, "1.2.3.4", net.ParseIP("1.2.3.4"))
		_, queryErr := client.Query(req, appsec.Policy{FailureAction: configuration.FailureActionPassthrough}, http.NewResponseController(rw))
		outcomes <- outcome{err: queryErr, elapsed: time.Since(started)}
		rw.WriteHeader(http.StatusForbidden)
	}))

	bodyReader, bodyWriter := io.Pipe()
	go func() { _, _ = bodyWriter.Write([]byte("partial")) }()
	go func() {
		res, doErr := http.Post(front.URL+"/stream", "application/octet-stream", bodyReader)
		if doErr == nil {
			_ = res.Body.Close()
		}
	}()

	got := <-outcomes
	_ = bodyWriter.Close()
	front.Close()
	if !errors.Is(got.err, appsec.ErrBodyReadTimeout) {
		fmt.Fprintf(os.Stderr, "Query error %%v, want ErrBodyReadTimeout\n", got.err)
		os.Exit(1)
	}
	if got.elapsed > 5*time.Second {
		fmt.Fprintf(os.Stderr, "Query returned after %%v, want about 1s\n", got.elapsed)
		os.Exit(1)
	}
}
`, yaegitest.ModulePath+"/pkg/appsec",
		yaegitest.ModulePath+"/pkg/clientrequest",
		yaegitest.ModulePath+"/pkg/configuration")
}
