package cache

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeRedis is an in-process RESP server over a string map. It mirrors the behavior measured
// against redis:7-alpine, including the error a non-positive EX earns.
type fakeRedis struct {
	mu       sync.Mutex
	store    map[string]string
	commands [][]string
	// missAll makes every read answer nil, which is how a replica that never caught up looks.
	missAll bool
}

// startFakeRedis serves RESP on a local port until the test ends.
func startFakeRedis(t *testing.T, missAll bool) (*fakeRedis, string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	fake := &fakeRedis{store: map[string]string{}, missAll: missAll}
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go fake.serve(conn)
		}
	}()
	return fake, listener.Addr().String()
}

func (f *fakeRedis) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	reader := bufio.NewReader(conn)
	for {
		args, err := readRESPCommand(reader)
		if err != nil {
			return
		}
		if _, writeErr := io.WriteString(conn, f.reply(args)); writeErr != nil {
			return
		}
	}
}

func (f *fakeRedis) reply(args []string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.commands = append(f.commands, append([]string(nil), args...))
	switch strings.ToUpper(args[0]) {
	case "GET":
		return f.bulk(args[1])
	case "MGET":
		reply := fmt.Sprintf("*%d\r\n", len(args)-1)
		for _, name := range args[1:] {
			reply += f.bulk(name)
		}
		return reply
	case "SET":
		// Real Redis rejects a non-positive EX; measured against redis:7-alpine.
		if len(args) >= 5 && strings.EqualFold(args[3], "EX") {
			if seconds, convErr := strconv.ParseInt(args[4], 10, 64); convErr != nil || seconds <= 0 {
				return "-ERR invalid expire time in 'set' command\r\n"
			}
		}
		f.store[args[1]] = args[2]
		return "+OK\r\n"
	case "DEL":
		delete(f.store, args[1])
		return ":1\r\n"
	case "EVALSHA":
		return "-NOSCRIPT No matching script. Please use EVAL.\r\n"
	case "EVAL":
		return f.evalAcquire(args)
	default:
		return "+OK\r\n"
	}
}

// bulk answers one key, or nil when it is absent or this server never caught up.
func (f *fakeRedis) bulk(name string) string {
	if f.missAll {
		return "$-1\r\n"
	}
	value, ok := f.store[name]
	if !ok {
		return "$-1\r\n"
	}
	return fmt.Sprintf("$%d\r\n%s\r\n", len(value), value)
}

// evalAcquire runs the lease script argv: EVAL <script> 1 <key> <value> <ttl>.
func (f *fakeRedis) evalAcquire(args []string) string {
	if len(args) < 6 {
		return ":0\r\n"
	}
	key, value, ttl := args[3], args[4], args[5]
	if seconds, convErr := strconv.ParseInt(ttl, 10, 64); convErr != nil || seconds <= 0 {
		return "-ERR invalid expire time in 'set' command script: fake, on @user_script:2.\r\n"
	}
	if _, exists := f.store[key]; exists {
		return ":0\r\n"
	}
	f.store[key] = value
	return ":1\r\n"
}

// set seeds a key without going through the client, which is how the writer's data is planted.
func (f *fakeRedis) set(key, value string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.store[key] = value
}

// sentVerbs is the uppercased first word of every command this server received.
func (f *fakeRedis) sentVerbs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	verbs := make([]string, 0, len(f.commands))
	for _, command := range f.commands {
		verbs = append(verbs, strings.ToUpper(command[0]))
	}
	return verbs
}

// countVerb is how many times this server received verb.
func (f *fakeRedis) countVerb(verb string) int {
	count := 0
	for _, got := range f.sentVerbs() {
		if got == verb {
			count++
		}
	}
	return count
}

// readRESPCommand reads one *N array of bulk strings.
func readRESPCommand(reader *bufio.Reader) ([]string, error) {
	header, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	header = strings.TrimRight(header, "\r\n")
	if len(header) == 0 || header[0] != '*' {
		return nil, io.ErrUnexpectedEOF
	}
	count, err := strconv.Atoi(header[1:])
	if err != nil || count <= 0 {
		return nil, io.ErrUnexpectedEOF
	}
	args := make([]string, 0, count)
	for range count {
		sizeLine, readErr := reader.ReadString('\n')
		if readErr != nil {
			return nil, readErr
		}
		sizeLine = strings.TrimRight(sizeLine, "\r\n")
		if len(sizeLine) == 0 || sizeLine[0] != '$' {
			return nil, io.ErrUnexpectedEOF
		}
		size, convErr := strconv.Atoi(sizeLine[1:])
		if convErr != nil || size < 0 {
			return nil, io.ErrUnexpectedEOF
		}
		payload := make([]byte, size+2)
		if _, readErr = io.ReadFull(reader, payload); readErr != nil {
			return nil, readErr
		}
		args = append(args, string(payload[:size]))
	}
	return args, nil
}
