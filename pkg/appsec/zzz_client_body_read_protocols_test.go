package appsec

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

// bodyReadProtocolTimeout bounds every wait in these tests so a regression fails instead of hanging.
const bodyReadProtocolTimeout = 10 * time.Second

// queryOutcome is what Query returned inside a real net/http handler.
type queryOutcome struct {
	protoMajor int
	err        error
}

// newQueryingFrontServer starts a real net/http server whose handler runs Query on the inbound request,
// the way the bouncer does inside Traefik. AppSec hits are counted; none are expected.
func newQueryingFrontServer(t *testing.T, http2 bool, readTimeout time.Duration) (*httptest.Server, <-chan struct{}, <-chan queryOutcome, *int32) {
	t.Helper()
	var appsecHits int32
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&appsecHits, 1)
		rw.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(appsecServer.Close)
	appsecURL, _ := url.Parse(appsecServer.URL)
	client := newQueryClient(appsecURL, appsecServer.Client())

	entered := make(chan struct{}, 1)
	outcomes := make(chan queryOutcome, 1)
	front := httptest.NewUnstartedServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		_, err := client.Query(withTestAddress(r), Policy{FailureAction: configuration.FailureActionBan})
		outcomes <- queryOutcome{protoMajor: r.ProtoMajor, err: err}
	}))
	front.Config.ReadTimeout = readTimeout
	front.Config.ErrorLog = log.New(io.Discard, "", 0)
	if http2 {
		front.EnableHTTP2 = true
		front.StartTLS()
	} else {
		front.Start()
	}
	t.Cleanup(front.Close)
	return front, entered, outcomes, &appsecHits
}

func waitQueryOutcome(t *testing.T, outcomes <-chan queryOutcome) queryOutcome {
	t.Helper()
	select {
	case got := <-outcomes:
		return got
	case <-time.After(bodyReadProtocolTimeout):
		t.Fatal("Query() did not return after the client body read failed")
		return queryOutcome{}
	}
}

func waitEntered(t *testing.T, entered <-chan struct{}) {
	t.Helper()
	select {
	case <-entered:
	case <-time.After(bodyReadProtocolTimeout):
		t.Fatal("front handler never ran")
	}
}

func assertBodyReadOutcome(t *testing.T, got queryOutcome, wantProto int, want error, appsecHits *int32) {
	t.Helper()
	if got.protoMajor != wantProto {
		t.Fatalf("request ProtoMajor=%d want %d", got.protoMajor, wantProto)
	}
	if !errors.Is(got.err, want) {
		t.Fatalf("Query() error %v want %v (a GetBody error here is the false ban)", got.err, want)
	}
	if hits := atomic.LoadInt32(appsecHits); hits != 0 {
		t.Fatalf("AppSec server called %d times, want 0", hits)
	}
}

// startHTTP2Upload posts a body that never completes over HTTP/2 and returns its cancel func.
func startHTTP2Upload(t *testing.T, front *httptest.Server) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	bodyReader, bodyWriter := io.Pipe()
	t.Cleanup(func() { _ = bodyWriter.Close() })
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, front.URL+"/upload", bodyReader)
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = 1 << 20
	go func() {
		_, _ = bodyWriter.Write([]byte(strings.Repeat("a", 1000)))
	}()
	go func() {
		resp, doErr := front.Client().Do(req)
		if doErr == nil {
			_ = resp.Body.Close()
		}
	}()
	return cancel
}

// startHTTP1Upload sends HTTP/1.1 headers and part of a Content-Length body on a raw TCP connection.
func startHTTP1Upload(t *testing.T, front *httptest.Server) *net.TCPConn {
	t.Helper()
	conn, err := net.Dial("tcp", front.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := fmt.Fprintf(conn, "POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 100000\r\n\r\n%s", strings.Repeat("a", 1000)); err != nil {
		t.Fatal(err)
	}
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatalf("dialed %T, want *net.TCPConn", conn)
	}
	return tcpConn
}

// Test_appsecQuery_clientBodyReadOverRealProtocols drives real net/http servers through the body-read
// failures a client can cause mid-upload. Upstream issue #395 / PR #401: a client that cancels an
// HTTP/2 upload must not be banned. Only a read failure while the client is still connected is
// ErrClientBodyRead (400); every disconnect is ErrClientDisconnected.
func Test_appsecQuery_clientBodyReadOverRealProtocols(t *testing.T) {
	t.Run("HTTP/2 stream reset (RST_STREAM CANCEL) is a disconnect", func(t *testing.T) {
		front, entered, outcomes, appsecHits := newQueryingFrontServer(t, true, 0)
		cancel := startHTTP2Upload(t, front)
		defer cancel()
		waitEntered(t, entered)
		cancel()
		assertBodyReadOutcome(t, waitQueryOutcome(t, outcomes), 2, ErrClientDisconnected, appsecHits)
	})

	t.Run("HTTP/2 read timeout on a slow upload is a client body read error", func(t *testing.T) {
		front, entered, outcomes, appsecHits := newQueryingFrontServer(t, true, 300*time.Millisecond)
		cancel := startHTTP2Upload(t, front)
		defer cancel()
		waitEntered(t, entered)
		assertBodyReadOutcome(t, waitQueryOutcome(t, outcomes), 2, ErrClientBodyRead, appsecHits)
	})

	t.Run("HTTP/1.1 clean close (FIN) is a disconnect", func(t *testing.T) {
		front, entered, outcomes, appsecHits := newQueryingFrontServer(t, false, 0)
		conn := startHTTP1Upload(t, front)
		waitEntered(t, entered)
		_ = conn.Close()
		assertBodyReadOutcome(t, waitQueryOutcome(t, outcomes), 1, ErrClientDisconnected, appsecHits)
	})

	t.Run("HTTP/1.1 TCP reset (RST) is a disconnect", func(t *testing.T) {
		front, entered, outcomes, appsecHits := newQueryingFrontServer(t, false, 0)
		conn := startHTTP1Upload(t, front)
		waitEntered(t, entered)
		_ = conn.SetLinger(0)
		_ = conn.Close()
		assertBodyReadOutcome(t, waitQueryOutcome(t, outcomes), 1, ErrClientDisconnected, appsecHits)
	})

	t.Run("HTTP/1.1 read timeout on a slow upload is a disconnect", func(t *testing.T) {
		front, entered, outcomes, appsecHits := newQueryingFrontServer(t, false, 300*time.Millisecond)
		startHTTP1Upload(t, front)
		waitEntered(t, entered)
		assertBodyReadOutcome(t, waitQueryOutcome(t, outcomes), 1, ErrClientDisconnected, appsecHits)
	})
}
