package cache

import (
	"bufio"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// leaseRedis is an in-process RESP stand-in that records verbs and implements SET-if-absent for EVAL/EVALSHA.
type leaseRedis struct {
	mu    sync.Mutex
	keys  map[string]string
	verbs []string
	ln    net.Listener
}

func startLeaseRedis(t *testing.T) *leaseRedis {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &leaseRedis{keys: map[string]string{}, ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go server.serve(conn)
		}
	}()
	return server
}

func (s *leaseRedis) addr() string {
	return s.ln.Addr().String()
}

func (s *leaseRedis) verbsCopy() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.verbs))
	copy(out, s.verbs)
	return out
}

func (s *leaseRedis) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	reader := bufio.NewReader(conn)
	for {
		argv, err := readRESPArray(reader)
		if err != nil {
			return
		}
		if len(argv) == 0 {
			return
		}
		verb := strings.ToUpper(argv[0])
		s.mu.Lock()
		s.verbs = append(s.verbs, verb)
		reply := s.replyLocked(verb, argv)
		s.mu.Unlock()
		if _, writeErr := conn.Write(reply); writeErr != nil {
			return
		}
	}
}

func (s *leaseRedis) replyLocked(verb string, argv []string) []byte {
	switch verb {
	case "GET":
		if len(argv) < 2 {
			return []byte("-ERR wrong number of arguments\r\n")
		}
		value, ok := s.keys[argv[1]]
		if !ok {
			return []byte("$-1\r\n")
		}
		return respBulk(value)
	case "SET":
		if len(argv) < 3 {
			return []byte("-ERR wrong number of arguments\r\n")
		}
		s.keys[argv[1]] = argv[2]
		return []byte("+OK\r\n")
	case "EVAL", "EVALSHA":
		// EVAL script numkeys key value ttl — SET only when the key is absent.
		if len(argv) < 6 {
			return []byte("-ERR wrong number of arguments\r\n")
		}
		key := argv[3]
		if _, exists := s.keys[key]; exists {
			return []byte(":0\r\n")
		}
		s.keys[key] = argv[4]
		return []byte(":1\r\n")
	default:
		return []byte("+OK\r\n")
	}
}

func respBulk(value string) []byte {
	return []byte("$" + strconv.Itoa(len(value)) + "\r\n" + value + "\r\n")
}

func readRESPArray(reader *bufio.Reader) ([]string, error) {
	header, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	header = strings.TrimSpace(header)
	if !strings.HasPrefix(header, "*") {
		return nil, io.ErrUnexpectedEOF
	}
	count, convErr := strconv.Atoi(header[1:])
	if convErr != nil || count < 0 {
		return nil, io.ErrUnexpectedEOF
	}
	argv := make([]string, 0, count)
	for range count {
		bulkHeader, bulkErr := reader.ReadString('\n')
		if bulkErr != nil {
			return nil, bulkErr
		}
		bulkHeader = strings.TrimSpace(bulkHeader)
		if !strings.HasPrefix(bulkHeader, "$") {
			return nil, io.ErrUnexpectedEOF
		}
		length, lenErr := strconv.Atoi(bulkHeader[1:])
		if lenErr != nil || length < 0 {
			return nil, io.ErrUnexpectedEOF
		}
		payload := make([]byte, length+2)
		if _, readErr := io.ReadFull(reader, payload); readErr != nil {
			return nil, readErr
		}
		argv = append(argv, string(payload[:length]))
	}
	return argv, nil
}

func Test_memoryAcquireSerializesMissAndSet(t *testing.T) {
	client := &Client{}
	client.New(logger.New("INFO", ""), false, "", nil, "", "", "")
	defer client.Close()

	const goroutines = 32
	var wins atomic.Int64
	var started sync.WaitGroup
	var release sync.WaitGroup
	started.Add(goroutines)
	release.Add(1)
	var done sync.WaitGroup
	done.Add(goroutines)
	for range goroutines {
		go func() {
			defer done.Done()
			started.Done()
			release.Wait()
			won, err := client.Acquire(context.Background(), "updated", "t", 10)
			if err != nil {
				t.Errorf("Acquire: %v", err)
				return
			}
			if won {
				wins.Add(1)
			}
		}()
	}
	started.Wait()
	release.Done()
	done.Wait()
	if got := wins.Load(); got != 1 {
		t.Fatalf("winners=%d, want 1", got)
	}
	got, err := client.Get("updated")
	if err != nil || got != "t" {
		t.Fatalf("Get after acquire got %q err %v", got, err)
	}
}

func Test_redisAcquireUsesEvalNotGetThenSet(t *testing.T) {
	server := startLeaseRedis(t)
	client := &Client{}
	client.New(logger.New("INFO", ""), true, server.addr(), nil, "", "", "sess")
	defer client.Close()

	won, err := client.Acquire(context.Background(), "updated", "t", 10)
	if err != nil || !won {
		t.Fatalf("first Acquire won=%v err=%v", won, err)
	}
	second, secondErr := client.Acquire(context.Background(), "updated", "t", 10)
	if secondErr != nil || second {
		t.Fatalf("second Acquire won=%v err=%v, want lose", second, secondErr)
	}

	verbs := server.verbsCopy()
	var sawEval bool
	for i, verb := range verbs {
		if verb == "GET" && i+1 < len(verbs) && verbs[i+1] == "SET" {
			t.Fatalf("acquire sent GET then SET: %v", verbs)
		}
		if verb == "EVAL" || verb == "EVALSHA" {
			sawEval = true
		}
	}
	if !sawEval {
		t.Fatalf("acquire sent no EVAL/EVALSHA: %v", verbs)
	}
}
