package cache

import (
	"testing"

	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func TestPackedWordRoundTrip(t *testing.T) {
	stored := Packed("t", 7)
	word, ok := stored.PackedWord()
	if !ok || stored.Kind() != "t" {
		t.Fatalf("packed %#v", stored)
	}
	id, packed := storedFromWord(word).PackedOriginID()
	if !packed || id != 7 {
		t.Fatalf("id %d packed %v", id, packed)
	}
	if stored.LeftoverOrigin() != "" {
		t.Fatal("packed must not expose a leftover suffix")
	}
}

func TestSetRemediationPackedIsWordNotConcat(t *testing.T) {
	client := &Client{}
	client.New(logger.New("ERROR", ""), false, "", nil, "", "", "")
	client.SetRemediation("203.0.113.10", Packed("t", 1), 60)
	got, err := client.GetManyStored([]string{"203.0.113.10"})
	if err != nil {
		t.Fatal(err)
	}
	if _, packed := got["203.0.113.10"].PackedWord(); !packed {
		t.Fatalf("ttl_map must hold a packed word, got %#v", got["203.0.113.10"])
	}
	kind, kindErr := client.Get("203.0.113.10")
	if kindErr != nil || kind != "t" {
		t.Fatalf("string Get must return kind only, got %q err %v", kind, kindErr)
	}
}

func TestLeftoverSetStillGetManyStored(t *testing.T) {
	client := &Client{}
	client.New(logger.New("ERROR", ""), false, "", nil, "", "", "")
	client.Set("203.0.113.10", RemediationWithOrigin("t", "crowdsec"), 60)
	got, err := client.GetManyStored([]string{"203.0.113.10"})
	if err != nil {
		t.Fatal(err)
	}
	if got["203.0.113.10"].LeftoverOrigin() != "crowdsec" {
		t.Fatalf("leftover %#v", got["203.0.113.10"])
	}
}
