package lapi

import (
	"bufio"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// testLeaseRedis is an in-process RESP stand-in for Eval acquire plus GET/SET.
type testLeaseRedis struct {
	mu   sync.Mutex
	keys map[string]string
	ln   net.Listener
}

func startTestLeaseRedis(t *testing.T) *testLeaseRedis {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &testLeaseRedis{keys: map[string]string{}, ln: ln}
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

func (s *testLeaseRedis) addr() string {
	return s.ln.Addr().String()
}

func (s *testLeaseRedis) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	reader := bufio.NewReader(conn)
	for {
		argv, err := readTestRESPArray(reader)
		if err != nil {
			return
		}
		if len(argv) == 0 {
			return
		}
		verb := strings.ToUpper(argv[0])
		s.mu.Lock()
		reply := s.replyLocked(verb, argv)
		s.mu.Unlock()
		if _, writeErr := conn.Write(reply); writeErr != nil {
			return
		}
	}
}

func (s *testLeaseRedis) replyLocked(verb string, argv []string) []byte {
	switch verb {
	case "GET":
		if len(argv) < 2 {
			return []byte("-ERR wrong number of arguments\r\n")
		}
		value, ok := s.keys[argv[1]]
		if !ok {
			return []byte("$-1\r\n")
		}
		return []byte("$" + strconv.Itoa(len(value)) + "\r\n" + value + "\r\n")
	case "SET":
		if len(argv) < 3 {
			return []byte("-ERR wrong number of arguments\r\n")
		}
		s.keys[argv[1]] = argv[2]
		return []byte("+OK\r\n")
	case "EVAL", "EVALSHA":
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

func readTestRESPArray(reader *bufio.Reader) ([]string, error) {
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
