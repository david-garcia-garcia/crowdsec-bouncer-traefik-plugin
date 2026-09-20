package decisionstore

import (
	"bufio"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// testStoreRedis is an in-process RESP stand-in for the verbs DecisionStore issues: GET, MGET, SET, DEL, MSETEX.
type testStoreRedis struct {
	mu   sync.Mutex
	keys map[string]string
	ln   net.Listener
}

// startTestStoreRedis listens on 127.0.0.1 and serves until the test ends.
func startTestStoreRedis(t *testing.T) *testStoreRedis {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &testStoreRedis{keys: map[string]string{}, ln: ln}
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

func (s *testStoreRedis) addr() string {
	return s.ln.Addr().String()
}

func (s *testStoreRedis) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	reader := bufio.NewReader(conn)
	for {
		argv, err := readTestStoreRESPArray(reader)
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

func (s *testStoreRedis) replyLocked(verb string, argv []string) []byte {
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
	case "MGET":
		if len(argv) < 2 {
			return []byte("-ERR wrong number of arguments\r\n")
		}
		var reply strings.Builder
		reply.WriteString("*" + strconv.Itoa(len(argv)-1) + "\r\n")
		for _, key := range argv[1:] {
			value, ok := s.keys[key]
			if !ok {
				reply.WriteString("$-1\r\n")
				continue
			}
			reply.WriteString("$" + strconv.Itoa(len(value)) + "\r\n" + value + "\r\n")
		}
		return []byte(reply.String())
	case "SET":
		if len(argv) < 3 {
			return []byte("-ERR wrong number of arguments\r\n")
		}
		s.keys[argv[1]] = argv[2]
		return []byte("+OK\r\n")
	case "MSETEX":
		// MSETEX numkeys key val [key val ...] EX|EXAT ttl
		if len(argv) < 6 {
			return []byte("-ERR wrong number of arguments\r\n")
		}
		numkeys, convErr := strconv.Atoi(argv[1])
		if convErr != nil || numkeys < 1 || len(argv) < 2+2*numkeys+2 {
			return []byte("-ERR wrong number of arguments\r\n")
		}
		for i := 0; i < numkeys; i++ {
			s.keys[argv[2+2*i]] = argv[2+2*i+1]
		}
		return []byte(":1\r\n")
	case "DEL":
		if len(argv) < 2 {
			return []byte("-ERR wrong number of arguments\r\n")
		}
		if _, exists := s.keys[argv[1]]; !exists {
			return []byte(":0\r\n")
		}
		delete(s.keys, argv[1])
		return []byte(":1\r\n")
	default:
		return []byte("+OK\r\n")
	}
}

func readTestStoreRESPArray(reader *bufio.Reader) ([]string, error) {
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
