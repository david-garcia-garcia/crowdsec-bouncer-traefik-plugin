package decisionstore

import (
	"bufio"
	"errors"
	"net"
	"testing"

	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
	simpleredis "github.com/david-garcia-garcia/traefik-middleware-utilities/simpleredis"
)

// startScriptedRedis accepts connections, reads each command, and answers with reply.
// An empty reply never answers, so every command runs into CommandTimeout.
func startScriptedRedis(t *testing.T, reply string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				reader := bufio.NewReader(conn)
				for {
					if _, readErr := readTestStoreRESPArray(reader); readErr != nil {
						return
					}
					if reply == "" {
						continue
					}
					if _, writeErr := conn.Write([]byte(reply)); writeErr != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// TestRedisTimeoutIsUnreachable is a Redis that does not answer within CommandTimeout: the lookup
// and the Range read report ErrUnreachable, and the timeout stays visible for the log line.
func TestRedisTimeoutIsUnreachable(t *testing.T) {
	store := NewRedis(logger.New("ERROR", ""), startScriptedRedis(t, ""), nil, "", "", "slow")
	t.Cleanup(store.Close)

	kind, _, _, err := store.LookupRemediation("203.0.113.50", net.ParseIP("203.0.113.50"), nil)
	if kind != "" || !errors.Is(err, ErrUnreachable) || !errors.Is(err, simpleredis.ErrTimeout) {
		t.Fatalf("lookup on a silent Redis: want no kind and ErrUnreachable wrapping redis:timeout, got kind %q err %v", kind, err)
	}
	_, err = store.RangeIndex()
	if !errors.Is(err, ErrUnreachable) || !errors.Is(err, simpleredis.ErrTimeout) {
		t.Fatalf("RangeIndex on a silent Redis: want ErrUnreachable wrapping redis:timeout, got %v", err)
	}
}

// TestRedisErrorReplyIsNotUnreachable is a Redis that answers with an error (here NOAUTH): that
// is configuration, not an outage, so it must not map to ErrUnreachable.
func TestRedisErrorReplyIsNotUnreachable(t *testing.T) {
	store := NewRedis(logger.New("ERROR", ""), startScriptedRedis(t, "-NOAUTH Authentication required.\r\n"), nil, "", "", "noauth")
	t.Cleanup(store.Close)

	kind, _, _, err := store.LookupRemediation("203.0.113.51", net.ParseIP("203.0.113.51"), nil)
	if kind != "" || err == nil || errors.Is(err, ErrUnreachable) {
		t.Fatalf("lookup on a NOAUTH reply: want no kind and a non-unreachable error, got kind %q err %v", kind, err)
	}
}
