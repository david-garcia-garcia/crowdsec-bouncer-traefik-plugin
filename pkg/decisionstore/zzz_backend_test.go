package decisionstore

import (
	"errors"
	"net"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

const (
	backendBanIP      = "203.0.113.10"
	backendRangeIP    = "10.1.2.3"
	backendRangeCIDR  = "10.0.0.0/8"
	backendOrigin     = "crowdsec"
	backendLiveTTLSec = int64(60)
	expandedV6        = "2001:0db8:0000:0000:0000:0000:0000:0001"
	compressedV6      = "2001:db8::1"
)

// testBackend is one DecisionStore constructor the shared contract runs against.
type testBackend struct {
	name string
	open func(*testing.T) *Store
}

// backendContract is one Put/Lookup/Delete/Range behavior both backends must share.
type backendContract struct {
	name  string
	check func(*testing.T, *Store)
}

func testBackends() []testBackend {
	return []testBackend{
		{
			name: "memory",
			open: func(t *testing.T) *Store {
				t.Helper()
				return NewMemory(logger.New("ERROR", ""))
			},
		},
		{
			name: "redis",
			open: func(t *testing.T) *Store {
				t.Helper()
				server := startTestStoreRedis(t)
				store := NewRedis(logger.New("ERROR", ""), server.addr(), nil, "", "", "sess")
				t.Cleanup(store.Close)
				return store
			},
		},
	}
}

func backendContracts() []backendContract {
	return []backendContract{
		{name: "emptyLookupMiss", check: checkEmptyLookupMiss},
		{name: "livePutIPBanThenDelete", check: checkLivePutIPBanThenDelete},
		{name: "streamTickPutVisibleAfterPublish", check: checkStreamTickPutVisibleAfterPublish},
		{name: "liveAllowMemoIsNotMiss", check: checkLiveAllowMemoIsNotMiss},
		{name: "headerBanDoesNotLeakToOtherHeader", check: checkHeaderBanDoesNotLeakToOtherHeader},
		{name: "headerBanOutranksIPCaptcha", check: checkHeaderBanOutranksIPCaptcha},
		{name: "ipBanSkipsRangeCaptcha", check: checkIPBanSkipsRangeCaptcha},
		{name: "rangeBanWhenIPIsCaptcha", check: checkRangeBanWhenIPIsCaptcha},
		{name: "rangeApplyThenRemove", check: checkRangeApplyThenRemove},
		{name: "ipv6SpellingsShareSlot", check: checkIPv6SpellingsShareSlot},
		{name: "putRangeScopeIsIgnored", check: checkPutRangeScopeIsIgnored},
	}
}

// TestBackendContract is Put/Lookup/Delete/Range through Store for memory and Redis.
// Tick isolation (Put hidden until PublishTick) and Redis TTL vs memory ExpiresAt are not in this matrix.
func TestBackendContract(t *testing.T) {
	for _, backend := range testBackends() {
		t.Run(backend.name, func(t *testing.T) {
			for _, contract := range backendContracts() {
				t.Run(contract.name, func(t *testing.T) {
					contract.check(t, backend.open(t))
				})
			}
		})
	}
}

func checkEmptyLookupMiss(t *testing.T, store *Store) {
	t.Helper()
	mustMiss(t, store, backendBanIP, nil)
}

func checkLivePutIPBanThenDelete(t *testing.T, store *Store) {
	t.Helper()
	store.Put(Decision{
		Scope: decisionscope.ScopeIP, Value: backendBanIP,
		Kind: decisionscope.BannedValue, Origin: backendOrigin, DurationSec: backendLiveTTLSec,
	})
	mustKind(t, store, backendBanIP, nil, decisionscope.BannedValue, backendOrigin)
	store.Delete(decisionscope.ScopeIP, backendBanIP)
	mustMiss(t, store, backendBanIP, nil)
}

func checkStreamTickPutVisibleAfterPublish(t *testing.T, store *Store) {
	t.Helper()
	store.BeginTick()
	store.Put(Decision{
		Scope: decisionscope.ScopeIP, Value: backendBanIP,
		Kind: decisionscope.BannedValue, Origin: backendOrigin, DurationSec: backendLiveTTLSec,
	})
	store.PublishTick(0)
	mustKind(t, store, backendBanIP, nil, decisionscope.BannedValue, backendOrigin)
}

func checkLiveAllowMemoIsNotMiss(t *testing.T, store *Store) {
	t.Helper()
	store.Put(Decision{
		Scope: decisionscope.ScopeIP, Value: backendBanIP,
		Kind: decisionscope.NoBannedValue, DurationSec: backendLiveTTLSec,
	})
	mustKind(t, store, backendBanIP, nil, decisionscope.NoBannedValue, "")
}

func checkHeaderBanDoesNotLeakToOtherHeader(t *testing.T, store *Store) {
	t.Helper()
	store.Put(Decision{
		Scope: decisionscope.ScopeCountry, Value: "fr",
		Kind: decisionscope.BannedValue, Origin: backendOrigin, DurationSec: backendLiveTTLSec,
	})
	mustKind(t, store, backendBanIP, map[string]string{decisionscope.ScopeCountry: "FR"}, decisionscope.BannedValue, backendOrigin)
	mustMiss(t, store, backendBanIP, map[string]string{decisionscope.ScopeCountry: "US"})
	mustMiss(t, store, backendBanIP, nil)
}

func checkHeaderBanOutranksIPCaptcha(t *testing.T, store *Store) {
	t.Helper()
	store.Put(Decision{
		Scope: decisionscope.ScopeIP, Value: backendBanIP,
		Kind: decisionscope.CaptchaValue, Origin: backendOrigin, DurationSec: backendLiveTTLSec,
	})
	store.Put(Decision{
		Scope: decisionscope.ScopeCountry, Value: "FR",
		Kind: decisionscope.BannedValue, Origin: backendOrigin, DurationSec: backendLiveTTLSec,
	})
	mustKind(t, store, backendBanIP, map[string]string{decisionscope.ScopeCountry: "FR"}, decisionscope.BannedValue, backendOrigin)
}

func checkIPBanSkipsRangeCaptcha(t *testing.T, store *Store) {
	t.Helper()
	store.Put(Decision{
		Scope: decisionscope.ScopeIP, Value: backendRangeIP,
		Kind: decisionscope.BannedValue, Origin: backendOrigin, DurationSec: backendLiveTTLSec,
	})
	if err := store.ApplyRangeBatch(map[string]string{backendRangeCIDR: decisionscope.CaptchaValue}, nil); err != nil {
		t.Fatal(err)
	}
	mustKind(t, store, backendRangeIP, nil, decisionscope.BannedValue, backendOrigin)
}

func checkRangeBanWhenIPIsCaptcha(t *testing.T, store *Store) {
	t.Helper()
	store.Put(Decision{
		Scope: decisionscope.ScopeIP, Value: backendRangeIP,
		Kind: decisionscope.CaptchaValue, Origin: backendOrigin, DurationSec: backendLiveTTLSec,
	})
	if err := store.ApplyRangeBatch(map[string]string{backendRangeCIDR: decisionscope.BannedValue}, nil); err != nil {
		t.Fatal(err)
	}
	mustKind(t, store, backendRangeIP, nil, decisionscope.BannedValue, "")
}

func checkRangeApplyThenRemove(t *testing.T, store *Store) {
	t.Helper()
	mustMiss(t, store, backendRangeIP, nil)
	if err := store.ApplyRangeBatch(map[string]string{backendRangeCIDR: decisionscope.BannedValue}, nil); err != nil {
		t.Fatal(err)
	}
	mustKind(t, store, backendRangeIP, nil, decisionscope.BannedValue, "")
	if err := store.ApplyRangeBatch(nil, []string{backendRangeCIDR}); err != nil {
		t.Fatal(err)
	}
	mustMiss(t, store, backendRangeIP, nil)
}

func checkIPv6SpellingsShareSlot(t *testing.T, store *Store) {
	t.Helper()
	store.Put(Decision{
		Scope: decisionscope.ScopeIP, Value: expandedV6,
		Kind: decisionscope.BannedValue, Origin: backendOrigin, DurationSec: backendLiveTTLSec,
	})
	mustKind(t, store, compressedV6, nil, decisionscope.BannedValue, backendOrigin)
	store.Delete(decisionscope.ScopeIP, expandedV6)
	mustMiss(t, store, compressedV6, nil)
}

func checkPutRangeScopeIsIgnored(t *testing.T, store *Store) {
	t.Helper()
	store.Put(Decision{
		Scope: decisionscope.ScopeRange, Value: backendRangeCIDR,
		Kind: decisionscope.BannedValue, DurationSec: backendLiveTTLSec,
	})
	mustMiss(t, store, backendRangeIP, nil)
}

// lookupRemediation is Store.LookupRemediation the way ServeHTTP does: remoteIP is ipAddr.String().
// Packed intern ids and Redis kind+origin strings resolve to the same origin name.
func lookupRemediation(store *Store, remoteIP string, scopes map[string]string) (string, string, error) {
	ipAddr := net.ParseIP(remoteIP)
	if ipAddr != nil {
		remoteIP = ipAddr.String()
	}
	kind, originName, originID, err := store.LookupRemediation(remoteIP, ipAddr, scopes)
	if originID != 0 {
		return kind, store.OriginName(originID), err
	}
	return kind, originName, err
}

func mustKind(t *testing.T, store *Store, remoteIP string, scopes map[string]string, wantKind, wantOrigin string) {
	t.Helper()
	kind, origin, err := lookupRemediation(store, remoteIP, scopes)
	if err != nil || kind != wantKind {
		t.Fatalf("kind %q err %v, want %q", kind, err, wantKind)
	}
	if origin != wantOrigin {
		t.Fatalf("origin %q, want %q", origin, wantOrigin)
	}
}

func mustMiss(t *testing.T, store *Store, remoteIP string, scopes map[string]string) {
	t.Helper()
	kind, _, err := lookupRemediation(store, remoteIP, scopes)
	if !errors.Is(err, ErrMiss) || err.Error() != "store:miss" {
		t.Fatalf("want store:miss, got kind %q err %v", kind, err)
	}
}
