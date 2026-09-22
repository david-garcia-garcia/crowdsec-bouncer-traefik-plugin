package instance

import (
	"bytes"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
)

type testClient struct {
	id string
}

func testLog() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})), &buf
}

func TestPublishSubscribeBeforeOwner(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)

	var bound atomic.Value
	bound.Store((*testClient)(nil))
	log, buf := testLog()
	Subscribe(LegLAPI, "shared", Subscriber{Value: &bound, TraefikName: "cs-admin", Log: log})
	loaded, _ := bound.Load().(*testClient)
	if loaded != nil {
		t.Fatal("subscribe before publish must leave typed nil")
	}
	if !strings.Contains(buf.String(), MsgUnbound) {
		t.Fatalf("empty subscribe must log unbound: %s", buf.String())
	}

	owner := &testClient{id: "A"}
	ownerLog, _ := testLog()
	if err := PublishAll([]PublishAttempt{{
		Leg: LegLAPI, InstanceName: "shared", Publisher: "cs", Client: owner, Empty: (*testClient)(nil), Log: ownerLog,
	}}); err != nil {
		t.Fatal(err)
	}
	loaded, _ = bound.Load().(*testClient)
	if loaded != owner {
		t.Fatal("publish must Store into existing subscribers before return")
	}
}

func TestIndependentLAPIAndAppSecSharedName(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)

	lapiClient := &testClient{id: "lapi"}
	appsecClient := &testClient{id: "appsec"}
	if err := PublishAll([]PublishAttempt{
		{Leg: LegLAPI, InstanceName: "shared", Publisher: "cs", Client: lapiClient, Empty: (*testClient)(nil)},
		{Leg: LegAppSec, InstanceName: "shared", Publisher: "cs", Client: appsecClient, Empty: (*testClient)(nil)},
	}); err != nil {
		t.Fatal(err)
	}
	Clear(LegLAPI, lapiClient, "cs")
	var appsecBound atomic.Value
	Subscribe(LegAppSec, "shared", Subscriber{Value: &appsecBound, TraefikName: "cs"})
	if appsecBound.Load() != appsecClient {
		t.Fatal("clearing LAPI shared must not clear AppSec shared")
	}
}

func TestSecondPublisherRejectedAndRollback(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)

	first := &testClient{id: "first"}
	if err := PublishAll([]PublishAttempt{{
		Leg: LegAppSec, InstanceName: "shared", Publisher: "cs-a", Client: first, Empty: (*testClient)(nil),
	}}); err != nil {
		t.Fatal(err)
	}
	freeLAPI := &testClient{id: "free"}
	takenAppSec := &testClient{id: "taken"}
	ownerLog, buf := testLog()
	err := PublishAll([]PublishAttempt{
		{Leg: LegLAPI, InstanceName: "api", Publisher: "cs-b", Client: freeLAPI, Empty: (*testClient)(nil), Log: ownerLog},
		{Leg: LegAppSec, InstanceName: "shared", Publisher: "cs-b", Client: takenAppSec, Empty: (*testClient)(nil), Log: ownerLog},
	})
	if err == nil {
		t.Fatal("second publisher on taken AppSec name must fail")
	}
	if !strings.Contains(buf.String(), MsgTaken) {
		t.Fatalf("must log name taken: %s", buf.String())
	}
	var lapiBound atomic.Value
	Subscribe(LegLAPI, "api", Subscriber{Value: &lapiBound, TraefikName: "sub"})
	loaded, _ := lapiBound.Load().(*testClient)
	if loaded != nil {
		t.Fatal("rejected multi-leg publish must unpublish the free LAPI name")
	}
	var shared atomic.Value
	Subscribe(LegAppSec, "shared", Subscriber{Value: &shared, TraefikName: "sub"})
	if shared.Load() != first {
		t.Fatal("first publisher must keep shared")
	}
}

func TestClearDoesNotUnbindReplacement(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)

	oldClient := &testClient{id: "A"}
	newClient := &testClient{id: "B"}
	var bound atomic.Value
	Subscribe(LegLAPI, "shared", Subscriber{Value: &bound, TraefikName: "cs-admin"})
	if err := PublishAll([]PublishAttempt{{
		Leg: LegLAPI, InstanceName: "shared", Publisher: "cs", Client: oldClient, Empty: (*testClient)(nil),
	}}); err != nil {
		t.Fatal(err)
	}
	if err := PublishAll([]PublishAttempt{{
		Leg: LegLAPI, InstanceName: "shared", Publisher: "cs", Client: newClient, Empty: (*testClient)(nil),
	}}); err != nil {
		t.Fatal(err)
	}
	Clear(LegLAPI, oldClient, "cs")
	if bound.Load() != newClient {
		t.Fatal("clear of dying A must not Store nil over B")
	}
}

func TestClearUnbindsWhenPublisherStringDiffers(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)

	owner := &testClient{id: "A"}
	var bound atomic.Value
	bound.Store((*testClient)(nil))
	Subscribe(LegLAPI, "shared", Subscriber{Value: &bound, TraefikName: "admin"})
	if err := PublishAll([]PublishAttempt{{
		Leg: LegLAPI, InstanceName: "shared", Publisher: "cs@file", Client: owner, Empty: (*testClient)(nil),
	}}); err != nil {
		t.Fatal(err)
	}
	Clear(LegLAPI, owner, "cs")
	if loaded, _ := bound.Load().(*testClient); loaded != nil {
		t.Fatal("Close must unbind even when the Traefik name string drifted")
	}
}

func TestUnsubscribeRemovesSubscriber(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)

	var bound atomic.Value
	bound.Store((*testClient)(nil))
	Subscribe(LegLAPI, "shared", Subscriber{Value: &bound, TraefikName: "old"})
	Unsubscribe(LegLAPI, "shared", &bound)
	owner := &testClient{id: "A"}
	if err := PublishAll([]PublishAttempt{{
		Leg: LegLAPI, InstanceName: "shared", Publisher: "cs", Client: owner, Empty: (*testClient)(nil),
	}}); err != nil {
		t.Fatal(err)
	}
	loaded, _ := bound.Load().(*testClient)
	if loaded != nil {
		t.Fatal("unsubscribed atomic must not receive later publish")
	}
}

func TestSameMiddlewareRepublishAllowed(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)

	first := &testClient{id: "A"}
	second := &testClient{id: "B"}
	if err := PublishAll([]PublishAttempt{{
		Leg: LegLAPI, InstanceName: "shared", Publisher: "cs", Client: first, Empty: (*testClient)(nil),
	}}); err != nil {
		t.Fatal(err)
	}
	if err := PublishAll([]PublishAttempt{{
		Leg: LegLAPI, InstanceName: "shared", Publisher: "cs", Client: second, Empty: (*testClient)(nil),
	}}); err != nil {
		t.Fatal(err)
	}
	var bound atomic.Value
	Subscribe(LegLAPI, "shared", Subscriber{Value: &bound, TraefikName: "cs"})
	if bound.Load() != second {
		t.Fatal("recorded publisher may replace its own client")
	}
}

func TestUnpublishOnlyWhenStillPublisher(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)

	owner := &testClient{id: "I"}
	if err := PublishAll([]PublishAttempt{{
		Leg: LegLAPI, InstanceName: "shared", Publisher: "cs", Client: owner, Empty: (*testClient)(nil),
	}}); err != nil {
		t.Fatal(err)
	}
	Unpublish(LegLAPI, "shared", owner, "other")
	var bound atomic.Value
	Subscribe(LegLAPI, "shared", Subscriber{Value: &bound, TraefikName: "sub"})
	if bound.Load() != owner {
		t.Fatal("a different middleware must not unpublish")
	}
	Unpublish(LegLAPI, "shared", owner, "cs")
	if loaded, _ := bound.Load().(*testClient); loaded != nil {
		t.Fatal("recorded publisher unpublish must clear")
	}
}

func TestPublisherRenameClearsOldName(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)

	owner := &testClient{id: "A"}
	var oldBound atomic.Value
	oldBound.Store((*testClient)(nil))
	Subscribe(LegLAPI, "shared", Subscriber{Value: &oldBound, TraefikName: "admin"})
	if err := PublishAll([]PublishAttempt{{
		Leg: LegLAPI, InstanceName: "shared", Publisher: "cs", Client: owner, Empty: (*testClient)(nil),
	}}); err != nil {
		t.Fatal(err)
	}
	if oldBound.Load() != owner {
		t.Fatal("first publish must bind the old name")
	}
	if err := PublishAll([]PublishAttempt{{
		Leg: LegLAPI, InstanceName: "other", Publisher: "cs", Client: owner, Empty: (*testClient)(nil),
	}}); err != nil {
		t.Fatal(err)
	}
	if loaded, _ := oldBound.Load().(*testClient); loaded != nil {
		t.Fatal("rename must unbind subscribers of the previous name")
	}
}

func TestClearPublisherDropsOwnedSlots(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)

	owner := &testClient{id: "A"}
	other := &testClient{id: "B"}
	var bound atomic.Value
	bound.Store((*testClient)(nil))
	Subscribe(LegLAPI, "shared", Subscriber{Value: &bound, TraefikName: "admin"})
	if err := PublishAll([]PublishAttempt{
		{Leg: LegLAPI, InstanceName: "shared", Publisher: "cs", Client: owner, Empty: (*testClient)(nil)},
		{Leg: LegLAPI, InstanceName: "kept", Publisher: "other", Client: other, Empty: (*testClient)(nil)},
	}); err != nil {
		t.Fatal(err)
	}
	ClearPublisher(LegLAPI, "cs")
	if loaded, _ := bound.Load().(*testClient); loaded != nil {
		t.Fatal("dropping the publisher must unbind its subscribers")
	}
	var kept atomic.Value
	Subscribe(LegLAPI, "kept", Subscriber{Value: &kept, TraefikName: "other-sub"})
	if kept.Load() != other {
		t.Fatal("ClearPublisher must not touch another middleware's slot")
	}
}
