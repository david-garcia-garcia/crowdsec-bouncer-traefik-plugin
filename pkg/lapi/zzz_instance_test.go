package lapi

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

func TestCachePrefix_RedisIncludesInstanceId(t *testing.T) {
	cfg := testStreamConfig("lapi.example:8080", 1)
	cfg.RedisCacheEnabled = true
	cfg.RedisCacheEffectiveInstanceID = "pod-a"
	prefix := CachePrefix(cfg)
	base := SessionHex(cfg)
	want := base + ":pod-a"
	if prefix != want {
		t.Fatalf("CachePrefix() = %q, want %q", prefix, want)
	}
	if prefix == base {
		t.Fatal("redis prefix must differ from session hex alone")
	}
}

func TestCachePrefix_MemoryOmitsInstanceId(t *testing.T) {
	cfg := testStreamConfig("lapi.example:8080", 1)
	if CachePrefix(cfg) != SessionHex(cfg) {
		t.Fatal("memory cache prefix must stay session hex only")
	}
}

func TestCachePrefix_LiveModeRedisUsesIdentityBase(t *testing.T) {
	cfg := testStreamConfig("lapi.example:8080", 1)
	cfg.CrowdsecMode = configuration.LiveMode
	cfg.RedisCacheEnabled = true
	cfg.RedisCacheEffectiveInstanceID = "pod-b"
	prefix := CachePrefix(cfg)
	want := IdentityHex(cfg) + ":pod-b"
	if prefix != want {
		t.Fatalf("live prefix = %q, want %q", prefix, want)
	}
}

func TestResolveCacheInstanceIdentity_Configured(t *testing.T) {
	cfg := testStreamConfig("lapi.example:8080", 1)
	cfg.RedisCacheEnabled = true
	cfg.RedisCacheInstanceId = "explicit-id"
	ResolveCacheInstanceIdentity(cfg, slog.Default())
	if cfg.RedisCacheEffectiveInstanceID != "explicit-id" {
		t.Fatalf("effective = %q", cfg.RedisCacheEffectiveInstanceID)
	}
}

func TestResolveCacheInstanceIdentity_Hostname(t *testing.T) {
	cfg := testStreamConfig("lapi.example:8080", 1)
	cfg.RedisCacheEnabled = true
	ResolveCacheInstanceIdentity(cfg, slog.Default())
	if cfg.RedisCacheEffectiveInstanceID == "" {
		t.Fatal("expected hostname or fallback")
	}
}

func TestCachePrefix_IsolatedStreamLeasePerInstance(t *testing.T) {
	host := serveRedisOK(t)
	log := slog.Default()

	cfgA := testStreamConfig("lapi.example:8080", 1)
	cfgA.RedisCacheEnabled = true
	cfgA.RedisCacheHost = host
	cfgA.RedisCacheEffectiveInstanceID = "instance-a"
	prefixA := CachePrefix(cfgA)

	cfgB := testStreamConfig("lapi.example:8080", 1)
	cfgB.RedisCacheEnabled = true
	cfgB.RedisCacheHost = host
	cfgB.RedisCacheEffectiveInstanceID = "instance-b"
	prefixB := CachePrefix(cfgB)

	clientA := &cache.Client{}
	clientA.New(log, true, host, nil, "", "", prefixA)
	defer clientA.Close()
	clientB := &cache.Client{}
	clientB.New(log, true, host, nil, "", "", prefixB)
	defer clientB.Close()

	clientA.Set("updated", "1", 60)
	got, err := clientB.Get("updated")
	if err == nil || got != "" {
		t.Fatalf("instance B must not see A lease: got %q err %v", got, err)
	}
}

func TestCachePrefix_SameSessionSameInstanceWarnAndWire(t *testing.T) {
	fast := testStreamConfig("lapi.example:8080", 1)
	fast.RedisCacheEnabled = true
	fast.RedisCacheEffectiveInstanceID = "same-pod"
	slow := testStreamConfig("lapi.example:8080", 600)
	slow.RedisCacheEnabled = true
	slow.RedisCacheEffectiveInstanceID = "same-pod"
	if CachePrefix(fast) != CachePrefix(slow) {
		t.Fatal("same LAPI session and instance must share one redis cache prefix for warn-and-wire")
	}
}

func serveRedisOK(t *testing.T) string {
	t.Helper()
	store := sync.Map{}
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
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				rd := bufio.NewReader(c)
				for {
					cmd, args, readErr := readRedisCommandTest(rd)
					if readErr != nil {
						return
					}
					switch cmd {
					case "GET":
						key := ""
						if len(args) > 0 {
							key = args[0]
						}
						if val, ok := store.Load(key); ok {
							s := val.(string)
							_, _ = c.Write([]byte("$" + strconv.Itoa(len(s)) + "\r\n" + s + "\r\n"))
						} else {
							_, _ = c.Write([]byte("$-1\r\n"))
						}
					case "SET":
						if len(args) >= 2 {
							store.Store(args[0], args[1])
						}
						_, _ = c.Write([]byte("+OK\r\n"))
					default:
						_, _ = c.Write([]byte("+OK\r\n"))
					}
				}
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func readRedisCommandTest(rd *bufio.Reader) (string, []string, error) {
	line, err := rd.ReadString('\n')
	if err != nil {
		return "", nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if strings.HasPrefix(line, "*") {
		count, convErr := strconv.Atoi(line[1:])
		if convErr != nil || count < 1 {
			return "", nil, io.ErrUnexpectedEOF
		}
		parts := make([]string, 0, count)
		for i := 0; i < count; i++ {
			head, headErr := rd.ReadString('\n')
			if headErr != nil {
				return "", nil, headErr
			}
			head = strings.TrimRight(head, "\r\n")
			if !strings.HasPrefix(head, "$") {
				return "", nil, io.ErrUnexpectedEOF
			}
			length, lenErr := strconv.Atoi(head[1:])
			if lenErr != nil || length < 0 {
				return "", nil, io.ErrUnexpectedEOF
			}
			buf := make([]byte, length+2)
			if _, readErr := io.ReadFull(rd, buf); readErr != nil {
				return "", nil, readErr
			}
			parts = append(parts, string(buf[:length]))
		}
		return strings.ToUpper(parts[0]), parts[1:], nil
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", nil, io.ErrUnexpectedEOF
	}
	return strings.ToUpper(fields[0]), fields[1:], nil
}
