package cache

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"

	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

type fakeRedisServer struct {
	mu    sync.Mutex
	store map[string]string
	fail  bool
}

func startFakeRedis(t *testing.T, store map[string]string, fail bool) (string, *fakeRedisServer) {
	t.Helper()
	if store == nil {
		store = map[string]string{}
	}
	fake := &fakeRedisServer{store: store, fail: fail}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go fake.serve(conn)
		}
	}()
	return listener.Addr().String(), fake
}

func (f *fakeRedisServer) serve(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	for {
		args, err := readRedisCommand(reader)
		if err != nil {
			return
		}
		f.mu.Lock()
		if f.fail {
			io.WriteString(conn, "-ERR fake\r\n")
			f.mu.Unlock()
			continue
		}
		switch args[0] {
		case "AUTH", "SELECT":
			io.WriteString(conn, "+OK\r\n")
		case "GET":
			io.WriteString(conn, bulkString(f.store, args[1]))
		case "MGET":
			fmt.Fprintf(conn, "*%d\r\n", len(args)-1)
			for _, name := range args[1:] {
				io.WriteString(conn, bulkString(f.store, name))
			}
		case "SET":
			f.store[args[1]] = args[2]
			io.WriteString(conn, "+OK\r\n")
		case "DEL":
			delete(f.store, args[1])
			io.WriteString(conn, ":1\r\n")
		default:
			io.WriteString(conn, "+OK\r\n")
		}
		f.mu.Unlock()
	}
}

func bulkString(store map[string]string, name string) string {
	value, found := store[name]
	if !found {
		return "$-1\r\n"
	}
	return fmt.Sprintf("$%d\r\n%s\r\n", len(value), value)
}

func readRedisCommand(reader *bufio.Reader) ([]string, error) {
	header, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	count, err := strconv.Atoi(header[1 : len(header)-2])
	if err != nil {
		return nil, err
	}
	args := make([]string, count)
	for i := 0; i < count; i++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		length, err := strconv.Atoi(line[1 : len(line)-2])
		if err != nil {
			return nil, err
		}
		buf := make([]byte, length+2)
		if _, err = io.ReadFull(reader, buf); err != nil {
			return nil, err
		}
		args[i] = string(buf[:length])
	}
	return args, nil
}

func newRedisTestClient(t *testing.T, writerAddr string, readerAddrs []string) *Client {
	t.Helper()
	client := &Client{}
	client.New(logger.New("INFO", ""), true, writerAddr, readerAddrs, "", "", "pfx")
	t.Cleanup(func() { client.Close() })
	return client
}

func Test_redisSetGetDelete(t *testing.T) {
	writerAddr, _ := startFakeRedis(t, map[string]string{}, false)
	client := newRedisTestClient(t, writerAddr, nil)

	if err := client.Set("1.2.3.4", BannedValue, 60); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := client.Get("1.2.3.4")
	if err != nil || got != BannedValue {
		t.Fatalf("Get = %q err %v", got, err)
	}
	if err := client.Delete("1.2.3.4"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := client.Get("1.2.3.4"); err == nil || err.Error() != CacheMiss {
		t.Fatalf("after Delete Get = %v", err)
	}
}

func Test_redisSetZeroDurationNoOp(t *testing.T) {
	writerAddr, fake := startFakeRedis(t, map[string]string{}, false)
	client := newRedisTestClient(t, writerAddr, nil)

	if err := client.Set("1.2.3.4", BannedValue, 0); err != nil {
		t.Fatalf("Set zero: %v", err)
	}
	fake.mu.Lock()
	_, stored := fake.store["pfx:1.2.3.4"]
	fake.mu.Unlock()
	if stored {
		t.Fatal("zero duration must not write to Redis")
	}
	if _, err := client.Get("1.2.3.4"); err == nil || err.Error() != CacheMiss {
		t.Fatalf("Get after zero Set = %v", err)
	}
}

func Test_redisSetDeleteErrors(t *testing.T) {
	writerAddr, _ := startFakeRedis(t, map[string]string{}, true)
	client := newRedisTestClient(t, writerAddr, nil)

	if err := client.Set("k", BannedValue, 10); err == nil {
		t.Fatal("Set want error")
	}
	if err := client.Delete("k"); err == nil {
		t.Fatal("Delete want error")
	}
}

func Test_redisGetMany(t *testing.T) {
	writerAddr, _ := startFakeRedis(t, map[string]string{"pfx:a": "t", "pfx:b": "c"}, false)
	client := newRedisTestClient(t, writerAddr, nil)

	got, err := client.GetMany([]string{"a", "missing", "b"})
	if err != nil {
		t.Fatalf("GetMany: %v", err)
	}
	if got["a"] != BannedValue || got["b"] != CaptchaValue {
		t.Fatalf("GetMany got %+v", got)
	}
	if _, ok := got["missing"]; ok {
		t.Fatal("missing key must be omitted")
	}
}

func Test_redisEmptyValueIsMiss(t *testing.T) {
	writerAddr, _ := startFakeRedis(t, map[string]string{"pfx:empty": ""}, false)
	client := newRedisTestClient(t, writerAddr, nil)

	if _, err := client.Get("empty"); err == nil || err.Error() != CacheMiss {
		t.Fatalf("empty value Get = %v", err)
	}
}

func Test_redisReadYourWrites(t *testing.T) {
	writerStore := map[string]string{}
	readerStore := map[string]string{}
	writerAddr, _ := startFakeRedis(t, writerStore, false)
	readerAddr, _ := startFakeRedis(t, readerStore, false)
	client := newRedisTestClient(t, writerAddr, []string{readerAddr})

	if err := client.Set("fresh", BannedValue, 60); err != nil {
		t.Fatalf("Set: %v", err)
	}
	// Replica has not received the key yet.
	got, err := client.Get("fresh")
	if err != nil || got != BannedValue {
		t.Fatalf("read-your-writes Get = %q err %v", got, err)
	}
	if _, ok := readerStore["pfx:fresh"]; ok {
		t.Fatal("read should not have used lagging replica for freshly written key")
	}

	gotMany, err := client.GetMany([]string{"fresh", "other"})
	if err != nil {
		t.Fatalf("GetMany: %v", err)
	}
	if gotMany["fresh"] != BannedValue {
		t.Fatalf("GetMany fresh = %+v", gotMany)
	}
}

func Test_redisSetErrorDoesNotMarkWritten(t *testing.T) {
	writerAddr, _ := startFakeRedis(t, map[string]string{}, true)
	readerAddr, _ := startFakeRedis(t, map[string]string{"pfx:k": "t"}, false)
	client := newRedisTestClient(t, writerAddr, []string{readerAddr})

	if err := client.Set("k", BannedValue, 10); err == nil {
		t.Fatal("Set want error")
	}
	rc := client.cache.(*redisCache)
	if _, ok := rc.writtenLocal.Load("k"); ok {
		t.Fatal("failed Set must not mark key for read-your-writes")
	}
}

func Test_redisUnreachableGetMany(t *testing.T) {
	client := &Client{}
	client.New(logger.New("INFO", ""), true, "127.0.0.1:1", nil, "", "", "p")
	defer client.Close()
	_, err := client.GetMany([]string{"k"})
	if err == nil || err.Error() != CacheUnreachable {
		t.Fatalf("GetMany unreachable got %v, want %s", err, CacheUnreachable)
	}
}

func Test_redisMissMapsFromSimpleredis(t *testing.T) {
	writerAddr, _ := startFakeRedis(t, map[string]string{}, false)
	client := newRedisTestClient(t, writerAddr, nil)
	_, err := client.Get("missing")
	if err == nil || err.Error() != CacheMiss {
		t.Fatalf("Get missing = %v", err)
	}
}
