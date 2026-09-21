package instance

import (
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func TestPublishPeekSameClient(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)
	log := logger.New("ERROR", "")
	client, _ := lapi.NewTestClient(log)
	if err := PublishLAPI("shared", client); err != nil {
		t.Fatal(err)
	}
	if PeekLAPI("shared") != client {
		t.Fatal("Peek must return the published client")
	}
	if err := PublishLAPI("shared", client); err != nil {
		t.Fatalf("republish same client must pass: %v", err)
	}
}

func TestPublishDifferentClientFails(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)
	log := logger.New("ERROR", "")
	first, _ := lapi.NewTestClient(log)
	second, _ := lapi.NewTestClient(log)
	if err := PublishLAPI("shared", first); err != nil {
		t.Fatal(err)
	}
	if err := PublishLAPI("shared", second); err == nil {
		t.Fatal("different client under the same name must fail")
	}
}

func TestPeekMissingIsNil(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)
	if PeekLAPI("missing") != nil {
		t.Fatal("missing name must Peek nil")
	}
}
