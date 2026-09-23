package reclaim

import (
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

type testClient struct {
	id string
}

func loaded(dest *atomic.Value) *testClient {
	client, _ := Unbox(dest).(*testClient)
	return client
}

func openValue(t *testing.T, key string, value any) {
	t.Helper()
	_, err := OpenWithHooks(context.Background(), key, slog.Default(), func() (any, Hooks, error) {
		return value, Hooks{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestWatchBeforeSetAlias(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)

	var bound atomic.Value
	Watch("alias:lapi:shared", &bound, (*testClient)(nil))
	if loaded(&bound) != nil {
		t.Fatal("watch before alias must leave typed nil")
	}
	owner := &testClient{id: "A"}
	openValue(t, "owner-a", owner)
	if err := SetAlias("owner-a", "alias:lapi:shared", "cs", "lapi"); err != nil {
		t.Fatal(err)
	}
	if loaded(&bound) != owner {
		t.Fatal("set alias must Store into existing watchers")
	}
}

func TestIndependentLAPIAndAppSecSharedName(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)

	lapiClient := &testClient{id: "lapi"}
	appsecClient := &testClient{id: "appsec"}
	openValue(t, "lapi-key", lapiClient)
	openValue(t, "appsec-key", appsecClient)
	if err := SetAlias("lapi-key", "alias:lapi:shared", "cs", "lapi"); err != nil {
		t.Fatal(err)
	}
	if err := SetAlias("appsec-key", "alias:appsec:shared", "cs", "appsec"); err != nil {
		t.Fatal(err)
	}
	ClearPublisher("cs", "lapi")
	var appsecBound atomic.Value
	Watch("alias:appsec:shared", &appsecBound, (*testClient)(nil))
	if loaded(&appsecBound) != appsecClient {
		t.Fatal("clearing LAPI shared must not clear AppSec shared")
	}
}

func TestSecondPublisherRejected(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)

	first := &testClient{id: "first"}
	second := &testClient{id: "second"}
	openValue(t, "a", first)
	openValue(t, "b", second)
	if err := SetAlias("a", "alias:lapi:shared", "cs-a", "lapi"); err != nil {
		t.Fatal(err)
	}
	if err := SetAlias("b", "alias:lapi:shared", "cs-b", "lapi"); err == nil {
		t.Fatal("second publisher on taken alias must fail")
	}
	var bound atomic.Value
	Watch("alias:lapi:shared", &bound, (*testClient)(nil))
	if loaded(&bound) != first {
		t.Fatal("first publisher must keep the alias")
	}
}

func TestDyingIncarnationDoesNotUnbindReplacement(t *testing.T) {
	ResetForTestWith(0)
	t.Cleanup(ResetForTest)

	oldClient := &testClient{id: "A"}
	newClient := &testClient{id: "B"}
	var bound atomic.Value
	Watch("alias:lapi:shared", &bound, (*testClient)(nil))
	ctxOld, cancelOld := context.WithCancel(context.Background())
	if _, err := OpenWithHooks(ctxOld, "old", slog.Default(), func() (any, Hooks, error) {
		return oldClient, Hooks{}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := SetAlias("old", "alias:lapi:shared", "cs", "lapi"); err != nil {
		t.Fatal(err)
	}
	openValue(t, "new", newClient)
	if err := SetAlias("new", "alias:lapi:shared", "cs", "lapi"); err != nil {
		t.Fatal(err)
	}
	cancelOld()
	time.Sleep(20 * time.Millisecond)
	if loaded(&bound) != newClient {
		t.Fatal("close of dying A must not Store nil over B")
	}
}

func TestUnwatchRemovesWatcher(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)

	var bound atomic.Value
	Watch("alias:lapi:shared", &bound, (*testClient)(nil))
	Unwatch("alias:lapi:shared", &bound)
	owner := &testClient{id: "A"}
	openValue(t, "owner", owner)
	if err := SetAlias("owner", "alias:lapi:shared", "cs", "lapi"); err != nil {
		t.Fatal(err)
	}
	if loaded(&bound) != nil {
		t.Fatal("unwatched atomic must not receive later alias")
	}
}

func TestPublisherRenameClearsOldName(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)

	owner := &testClient{id: "A"}
	var oldBound atomic.Value
	Watch("alias:lapi:shared", &oldBound, (*testClient)(nil))
	openValue(t, "owner", owner)
	if err := SetAlias("owner", "alias:lapi:shared", "cs", "lapi"); err != nil {
		t.Fatal(err)
	}
	if loaded(&oldBound) != owner {
		t.Fatal("first alias must bind the old name")
	}
	if err := SetAlias("owner", "alias:lapi:other", "cs", "lapi"); err != nil {
		t.Fatal(err)
	}
	if loaded(&oldBound) != nil {
		t.Fatal("rename must unbind watchers of the previous name")
	}
}

func TestClearPublisherDropsOwnedAliases(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)

	owner := &testClient{id: "A"}
	other := &testClient{id: "B"}
	var bound atomic.Value
	Watch("alias:lapi:shared", &bound, (*testClient)(nil))
	openValue(t, "owner", owner)
	openValue(t, "other", other)
	if err := SetAlias("owner", "alias:lapi:shared", "cs", "lapi"); err != nil {
		t.Fatal(err)
	}
	if err := SetAlias("other", "alias:lapi:kept", "other", "lapi"); err != nil {
		t.Fatal(err)
	}
	ClearPublisher("cs", "lapi")
	if loaded(&bound) != nil {
		t.Fatal("dropping the publisher must unbind its watchers")
	}
	var kept atomic.Value
	Watch("alias:lapi:kept", &kept, (*testClient)(nil))
	if loaded(&kept) != other {
		t.Fatal("ClearPublisher must not touch another middleware's alias")
	}
}
