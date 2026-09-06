package simpleredis

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

type fakeRedis struct {
	mu      sync.Mutex
	store   map[string]string
	conns   int
	auths   int
	selects int
	gets    int
}

func startFakeRedis(t *testing.T, store map[string]string) (*fakeRedis, string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	fake := &fakeRedis{store: store}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			fake.mu.Lock()
			fake.conns++
			fake.mu.Unlock()
			go fake.serve(conn)
		}
	}()
	return fake, listener.Addr().String()
}

func (f *fakeRedis) serve(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	for {
		args, err := readCommand(reader)
		if err != nil {
			return
		}
		f.mu.Lock()
		switch args[0] {
		case "AUTH":
			f.auths++
			io.WriteString(conn, "+OK\r\n")
		case "SELECT":
			f.selects++
			io.WriteString(conn, "+OK\r\n")
		case "GET":
			f.gets++
			io.WriteString(conn, bulk(f.store, args[1]))
		case "MGET":
			fmt.Fprintf(conn, "*%d\r\n", len(args)-1)
			for _, name := range args[1:] {
				io.WriteString(conn, bulk(f.store, name))
			}
		case "SET":
			f.store[args[1]] = args[2]
			io.WriteString(conn, "+OK\r\n")
		default:
			io.WriteString(conn, "+OK\r\n")
		}
		f.mu.Unlock()
	}
}

func (f *fakeRedis) connections() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.conns
}

// handshakeCounts returns AUTH, SELECT, and GET commands seen on this fake.
func (f *fakeRedis) handshakeCounts() (auths, selects, gets int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.auths, f.selects, f.gets
}
func bulk(store map[string]string, name string) string {
	value, found := store[name]
	if !found {
		return "$-1\r\n"
	}
	return fmt.Sprintf("$%d\r\n%s\r\n", len(value), value)
}

func readCommand(reader *bufio.Reader) ([]string, error) {
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

func startStaticRedis(t *testing.T, reply string) string {
	t.Helper()
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
			go func(conn net.Conn) {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				for {
					if _, err := readCommand(reader); err != nil {
						return
					}
					io.WriteString(conn, reply)
				}
			}(conn)
		}
	}()
	return listener.Addr().String()
}

func TestGetHitAndMiss(t *testing.T) {
	_, addr := startFakeRedis(t, map[string]string{"hit": "t"})
	var redis SimpleRedis
	redis.Init(addr, "", "")

	got, err := redis.Get("hit")
	if err != nil {
		t.Fatalf("Get hit: %v", err)
	}
	if string(got) != "t" {
		t.Fatalf("Get hit = %q, want %q", got, "t")
	}

	if _, err = redis.Get("missing"); err == nil || err.Error() != RedisMiss {
		t.Fatalf("Get missing = %v, want %s", err, RedisMiss)
	}
}

func TestConnectionIsReused(t *testing.T) {
	fake, addr := startFakeRedis(t, map[string]string{"hit": "t"})
	var redis SimpleRedis
	redis.Init(addr, "", "")

	for i := 0; i < 25; i++ {
		if _, err := redis.Get("hit"); err != nil {
			t.Fatalf("Get %d: %v", i, err)
		}
	}
	if fake.connections() != 1 {
		t.Fatalf("25 sequential Get opened %d connections, want 1", fake.connections())
	}
}

func TestConcurrentCommandsStayWithinPool(t *testing.T) {
	block := make(chan struct{})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	var peak int
	var mu sync.Mutex
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			peak++
			mu.Unlock()
			go func(c net.Conn) {
				defer c.Close()
				reader := bufio.NewReader(c)
				if _, err := readCommand(reader); err != nil {
					return
				}
				<-block
				io.WriteString(c, "$1\r\nt\r\n")
			}(conn)
		}
	}()

	var redis SimpleRedis
	redis.Init(listener.Addr().String(), "", "")

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = redis.Get("hit")
		}()
	}
	time.Sleep(100 * time.Millisecond)
	close(block)
	wg.Wait()

	mu.Lock()
	got := peak
	mu.Unlock()
	if got > maxOpenConns {
		t.Fatalf("16 concurrent Get opened peak %d connections, want at most %d", got, maxOpenConns)
	}
}

func TestValueWithNewlinesSurvives(t *testing.T) {
	index := "10.0.0.0/8\n192.168.0.0/16\n172.16.0.0/12"
	_, addr := startFakeRedis(t, map[string]string{})
	var redis SimpleRedis
	redis.Init(addr, "", "")

	if err := redis.Set("range-index", []byte(index), 60); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := redis.Get("range-index")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != index {
		t.Fatalf("Get = %q, want %q", got, index)
	}
}

func TestMGetHitsMissesAndEmpty(t *testing.T) {
	fake, addr := startFakeRedis(t, map[string]string{"a": "t", "c": "f"})
	var redis SimpleRedis
	redis.Init(addr, "", "")

	got, err := redis.MGet([]string{"a", "b", "c"})
	if err != nil {
		t.Fatalf("MGet: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("MGet returned %d values, want 3", len(got))
	}
	if string(got[0]) != "t" || got[1] != nil || string(got[2]) != "f" {
		t.Fatalf("MGet = %q, want [t <nil> f]", got)
	}

	empty, err := redis.MGet(nil)
	if empty != nil || err != nil {
		t.Fatalf("MGet(nil) = %v, %v, want nil, nil", empty, err)
	}
	if fake.connections() != 1 {
		t.Fatalf("MGet opened %d connections, want 1", fake.connections())
	}
}

func TestMGetKeepsValuesWithNewlinesAligned(t *testing.T) {
	index := "10.0.0.0/8\n192.168.0.0/16"
	_, addr := startFakeRedis(t, map[string]string{"range-index": index, "a": "t", "c": "f"})
	var redis SimpleRedis
	redis.Init(addr, "", "")

	got, err := redis.MGet([]string{"range-index", "a", "c"})
	if err != nil {
		t.Fatalf("MGet: %v", err)
	}
	if string(got[0]) != index || string(got[1]) != "t" || string(got[2]) != "f" {
		t.Fatalf("MGet = %q, want [%q t f]", got, index)
	}
}

func TestMGetRejectsShortReply(t *testing.T) {
	addr := startStaticRedis(t, "*2\r\n$1\r\nt\r\n$1\r\nf\r\n")
	var redis SimpleRedis
	redis.Init(addr, "", "")

	if _, err := redis.MGet([]string{"a", "b", "c"}); err == nil || err.Error() != RedisIssue {
		t.Fatalf("MGet with 2 values for 3 keys = %v, want %s", err, RedisIssue)
	}
}

func TestRejectedAuthIsReturned(t *testing.T) {
	addr := startStaticRedis(t, "-NOAUTH Authentication required.\r\n")
	var redis SimpleRedis
	redis.Init(addr, "", "")

	if _, err := redis.Get("a"); err == nil || err.Error() != RedisNoAuth {
		t.Fatalf("Get against -NOAUTH = %v, want %s", err, RedisNoAuth)
	}
}

func TestSetReturnsReplyError(t *testing.T) {
	addr := startStaticRedis(t, "-ERR value is not an integer or out of range\r\n")
	var redis SimpleRedis
	redis.Init(addr, "", "")

	err := redis.Set("k", []byte("v"), -1)
	if err == nil {
		t.Fatal("Set swallowed the error reply")
	}
	if err.Error() != "ERR value is not an integer or out of range" {
		t.Fatalf("Set = %v", err)
	}
}

func TestDelSucceeds(t *testing.T) {
	addr := startStaticRedis(t, "+OK\r\n")
	var redis SimpleRedis
	redis.Init(addr, "", "")

	if err := redis.Del("k"); err != nil {
		t.Fatalf("Del = %v", err)
	}
}

func TestUnreachableHost(t *testing.T) {
	var redis SimpleRedis
	redis.Init("127.0.0.1:1", "", "")

	if _, err := redis.Get("a"); err == nil || err.Error() != RedisUnreachable {
		t.Fatalf("Get = %v, want %s", err, RedisUnreachable)
	}
	if _, err := redis.MGet([]string{"a"}); err == nil || err.Error() != RedisUnreachable {
		t.Fatalf("MGet = %v, want %s", err, RedisUnreachable)
	}
}

func TestStaleConnectionIsRetried(t *testing.T) {
	fake, addr := startFakeRedis(t, map[string]string{"hit": "t"})
	var redis SimpleRedis
	redis.Init(addr, "", "")

	if _, err := redis.Get("hit"); err != nil {
		t.Fatalf("first Get: %v", err)
	}

	redis.mu.Lock()
	for _, conn := range redis.idle {
		conn.close()
		redis.open--
	}
	redis.idle = nil
	redis.mu.Unlock()

	got, err := redis.Get("hit")
	if err != nil {
		t.Fatalf("Get on a dead pooled connection: %v", err)
	}
	if string(got) != "t" {
		t.Fatalf("Get = %q, want %q", got, "t")
	}
	if fake.connections() != 2 {
		t.Fatalf("opened %d connections, want 2", fake.connections())
	}
}

func TestCloseDuringDialDoesNotAddConnection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	allowAccept := make(chan struct{})
	connOut := make(chan net.Conn, 1)
	go func() {
		<-allowAccept
		conn, err := listener.Accept()
		if err == nil {
			connOut <- conn
		}
	}()

	var redis SimpleRedis
	redis.Init(listener.Addr().String(), "", "")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = redis.Get("hit")
	}()
	time.Sleep(50 * time.Millisecond)
	redis.Close()
	close(allowAccept)
	select {
	case conn := <-connOut:
		conn.Close()
	case <-time.After(time.Second):
	}
	wg.Wait()

	if _, err := redis.Get("hit"); err == nil || err.Error() != RedisUnreachable {
		t.Fatalf("Get after Close = %v, want %s", err, RedisUnreachable)
	}
	if len(connOut) > 0 {
		// conn may have been accepted after Close; it must not stay in the pool.
	}
}

func TestOversizedBulkIsRejected(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		if _, err := readCommand(reader); err != nil {
			return
		}
		fmt.Fprintf(conn, "$%d\r\n", maxBulkBytes+1)
	}()

	var redis SimpleRedis
	redis.Init(listener.Addr().String(), "", "")
	if _, err := redis.Get("k"); err == nil || err.Error() != RedisIssue {
		t.Fatalf("Get = %v, want %s", err, RedisIssue)
	}
}

func TestOversizedArrayIsRejected(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		if _, err := readCommand(reader); err != nil {
			return
		}
		fmt.Fprintf(conn, "*%d\r\n", maxArrayCount+1)
	}()

	var redis SimpleRedis
	redis.Init(listener.Addr().String(), "", "")
	if _, err := redis.MGet([]string{"a"}); err == nil || err.Error() != RedisIssue {
		t.Fatalf("MGet = %v, want %s", err, RedisIssue)
	}
}

func TestNoAuthOnReusedConnDoesNotRepool(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	type connState struct {
		gets int
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				state := &connState{}
				reader := bufio.NewReader(c)
				for {
					args, err := readCommand(reader)
					if err != nil {
						return
					}
					if args[0] == "GET" {
						state.gets++
						if state.gets == 1 {
							io.WriteString(c, "$1\r\nt\r\n")
							continue
						}
						io.WriteString(c, "-NOAUTH Authentication required.\r\n")
						continue
					}
					io.WriteString(c, "+OK\r\n")
				}
			}(conn)
		}
	}()

	var redis SimpleRedis
	redis.Init(listener.Addr().String(), "", "")
	if _, err := redis.Get("hit"); err != nil {
		t.Fatalf("first Get: %v", err)
	}
	if _, err := redis.Get("hit"); err == nil || err.Error() != RedisNoAuth {
		t.Fatalf("second Get = %v, want %s", err, RedisNoAuth)
	}
	if _, err := redis.Get("hit"); err != nil {
		t.Fatalf("third Get after NOAUTH: %v", err)
	}
}

func TestDialAuthFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		if _, err := readCommand(reader); err != nil {
			return
		}
		io.WriteString(conn, "-WRONGPASS invalid password\r\n")
	}()

	var redis SimpleRedis
	redis.Init(listener.Addr().String(), "bad", "")
	if _, err := redis.Get("k"); err == nil || err.Error() != RedisNoAuth {
		t.Fatalf("Get = %v, want %s", err, RedisNoAuth)
	}
}

func TestSetDelMGetAfterClose(t *testing.T) {
	fake, addr := startFakeRedis(t, map[string]string{})
	var redis SimpleRedis
	redis.Init(addr, "", "")
	redis.Close()

	if err := redis.Set("k", []byte("v"), 60); err == nil || err.Error() != RedisUnreachable {
		t.Fatalf("Set after Close = %v, want %s", err, RedisUnreachable)
	}
	if err := redis.Del("k"); err == nil || err.Error() != RedisUnreachable {
		t.Fatalf("Del after Close = %v, want %s", err, RedisUnreachable)
	}
	if _, err := redis.MGet([]string{"k"}); err == nil || err.Error() != RedisUnreachable {
		t.Fatalf("MGet after Close = %v, want %s", err, RedisUnreachable)
	}
	if fake.connections() != 0 {
		t.Fatalf("after Close opened %d connections, want 0", fake.connections())
	}
}

func TestGetUnexpectedReplyShape(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		if _, err := readCommand(reader); err != nil {
			return
		}
		io.WriteString(conn, "*2\r\n$1\r\na\r\n$1\r\nb\r\n")
	}()

	var redis SimpleRedis
	redis.Init(listener.Addr().String(), "", "")
	if _, err := redis.Get("k"); err == nil || err.Error() != RedisIssue {
		t.Fatalf("Get = %v, want %s", err, RedisIssue)
	}
}

func TestCloseDrainsIdleAndDoesNotRepool(t *testing.T) {
	fake, addr := startFakeRedis(t, map[string]string{"hit": "t"})
	var redis SimpleRedis
	redis.Init(addr, "", "")

	if _, err := redis.Get("hit"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(redis.idle) != 1 {
		t.Fatalf("after Get idle = %d, want 1", len(redis.idle))
	}

	redis.Close()
	if len(redis.idle) != 0 {
		t.Fatalf("after Close idle = %d, want 0", len(redis.idle))
	}
	redis.Close()

	if _, err := redis.Get("hit"); err == nil || err.Error() != RedisUnreachable {
		t.Fatalf("Get after Close = %v, want %s", err, RedisUnreachable)
	}
	if fake.connections() != 1 {
		t.Fatalf("Get after Close opened %d connections, want 1", fake.connections())
	}
	if len(redis.idle) != 0 {
		t.Fatalf("release after Close idle = %d, want 0", len(redis.idle))
	}
}

func TestAuthAndSelectOncePerDial(t *testing.T) {
	fake, addr := startFakeRedis(t, map[string]string{"hit": "t"})
	var redis SimpleRedis
	redis.Init(addr, "secret", "2")

	for i := 0; i < 3; i++ {
		if _, err := redis.Get("hit"); err != nil {
			t.Fatalf("Get %d: %v", i, err)
		}
	}
	auths, selects, gets := fake.handshakeCounts()
	if fake.connections() != 1 {
		t.Fatalf("opened %d connections, want 1", fake.connections())
	}
	if auths != 1 || selects != 1 || gets != 3 {
		t.Fatalf("AUTH=%d SELECT=%d GET=%d, want 1, 1, 3", auths, selects, gets)
	}
}

func TestTimeoutOnReusedConnIsNotRetried(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	var accepts int
	var mu sync.Mutex
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			accepts++
			mu.Unlock()
			go func(conn net.Conn) {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				if _, err := readCommand(reader); err != nil {
					return
				}
				io.WriteString(conn, "$1\r\nt\r\n")
				time.Sleep(3 * time.Second)
			}(conn)
		}
	}()

	var redis SimpleRedis
	redis.Init(listener.Addr().String(), "", "")
	if _, err := redis.Get("hit"); err != nil {
		t.Fatalf("first Get: %v", err)
	}
	if _, err := redis.Get("hit"); err == nil || err.Error() != RedisTimeout {
		t.Fatalf("second Get = %v, want %s", err, RedisTimeout)
	}
	mu.Lock()
	got := accepts
	mu.Unlock()
	if got != 1 {
		t.Fatalf("opened %d connections, want 1 (timeout must not retry)", got)
	}
}

func TestIoTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(3 * time.Second)
	}()

	var redis SimpleRedis
	redis.Init(listener.Addr().String(), "", "")
	if _, err := redis.Get("hit"); err == nil || err.Error() != RedisTimeout {
		t.Fatalf("Get = %v, want %s", err, RedisTimeout)
	}
}

func TestIdleTimeoutOpensANewConnection(t *testing.T) {
	fake, addr := startFakeRedis(t, map[string]string{"hit": "t"})
	var redis SimpleRedis
	redis.Init(addr, "", "")

	if _, err := redis.Get("hit"); err != nil {
		t.Fatalf("first Get: %v", err)
	}
	redis.mu.Lock()
	if len(redis.idle) != 1 {
		redis.mu.Unlock()
		t.Fatalf("idle = %d, want 1", len(redis.idle))
	}
	redis.idle[0].lastUsed = time.Now().Add(-idleTimeout - time.Second)
	redis.mu.Unlock()

	if _, err := redis.Get("hit"); err != nil {
		t.Fatalf("Get after idle timeout: %v", err)
	}
	if fake.connections() != 2 {
		t.Fatalf("opened %d connections, want 2", fake.connections())
	}
}
