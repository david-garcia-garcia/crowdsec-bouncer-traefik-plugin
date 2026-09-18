package decisionscope

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// staleRedis is an in-process RESP server. With laggingReplica set it answers every read as a miss,
// which is how a read host that has not received the writer's latest decisions looks to the plugin.
type staleRedis struct {
	mu             sync.Mutex
	store          map[string]string
	laggingReplica bool
}

func startStaleRedis(t *testing.T, laggingReplica bool) (*staleRedis, string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	server := &staleRedis{store: map[string]string{}, laggingReplica: laggingReplica}
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go server.serve(conn)
		}
	}()
	return server, listener.Addr().String()
}

func (s *staleRedis) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	reader := bufio.NewReader(conn)
	for {
		args, err := readCommand(reader)
		if err != nil {
			return
		}
		if _, writeErr := io.WriteString(conn, s.reply(args)); writeErr != nil {
			return
		}
	}
}

func (s *staleRedis) reply(args []string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch strings.ToUpper(args[0]) {
	case "GET":
		return s.bulk(args[1])
	case "MGET":
		reply := fmt.Sprintf("*%d\r\n", len(args)-1)
		for _, name := range args[1:] {
			reply += s.bulk(name)
		}
		return reply
	case "SET":
		s.store[args[1]] = args[2]
		return "+OK\r\n"
	case "DEL":
		delete(s.store, args[1])
		return ":1\r\n"
	default:
		return "+OK\r\n"
	}
}

func (s *staleRedis) bulk(name string) string {
	if s.laggingReplica {
		return "$-1\r\n"
	}
	value, ok := s.store[name]
	if !ok {
		return "$-1\r\n"
	}
	return fmt.Sprintf("$%d\r\n%s\r\n", len(value), value)
}

func (s *staleRedis) get(key string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.store[key]
}

func (s *staleRedis) set(key, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store[key] = value
}

func readCommand(reader *bufio.Reader) ([]string, error) {
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
	for i := 0; i < count; i++ {
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

// laggingReplicaCache is a cache client whose one read host never caught up with the writer.
func laggingReplicaCache(t *testing.T) (*cache.Client, *staleRedis) {
	t.Helper()
	writer, writerAddr := startStaleRedis(t, false)
	_, replicaAddr := startStaleRedis(t, true)
	client := &cache.Client{}
	client.New(logger.New("INFO", ""), true, writerAddr, []string{replicaAddr}, "", "", "p")
	t.Cleanup(client.Close)
	return client, writer
}

// Test_LookupCachedRemediationSeesAJustStoredBan is the decision flip this ticket exists for.
// The stream poller stores the ban on the writer; the very next request read it back from a read
// host that had not received it yet, and stream and alone mode read that miss as "no decision
// affecting this IP", so the plugin served the request it had already decided to block.
func Test_LookupCachedRemediationSeesAJustStoredBan(t *testing.T) {
	cacheClient, _ := laggingReplicaCache(t)

	// What storeStreamDecision does when the stream delta carries a ban for this IP.
	cacheClient.Set("1.2.3.4", BannedValue, 60)

	value, _, err := LookupCachedRemediation(cacheClient, "1.2.3.4", net.ParseIP("1.2.3.4"), nil, nil)
	if err != nil {
		t.Fatalf("LookupCachedRemediation err %v, want the ban we had just stored", err)
	}
	if !IsActiveRemediation(value) {
		t.Fatalf("LookupCachedRemediation = %q, want an active remediation: the request would be served", value)
	}
}

// Test_ApplyRangeBatchKeepsCIDRsWhenTheReplicaLags is the same lag doing durable damage. The batch
// is a read-modify-write of one shared blob, so a stale read rebuilt the index from an old base and
// wrote that truncated blob back to the writer, dropping Range bans for every instance at once.
func Test_ApplyRangeBatchKeepsCIDRsWhenTheReplicaLags(t *testing.T) {
	cacheClient, writer := laggingReplicaCache(t)
	writer.set("p:"+RangeIndexKey, "10.0.0.0/8="+BannedValue)

	ApplyRangeBatch(cacheClient, map[string]string{"192.168.0.0/16": BannedValue}, nil)

	index := writer.get("p:" + RangeIndexKey)
	if !strings.Contains(index, "10.0.0.0/8") {
		t.Fatalf("range index = %q, want the existing 10.0.0.0/8 ban kept", index)
	}
	if !strings.Contains(index, "192.168.0.0/16") {
		t.Fatalf("range index = %q, want the new 192.168.0.0/16 ban added", index)
	}
}
