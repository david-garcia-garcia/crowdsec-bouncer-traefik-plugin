package bouncer

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

// TestStoreBinding_ConcurrentUnboxVsStore fails if storeBinding mutates Box.Value
// in place while loadedLAPI Unboxes the same published pointer.
func TestStoreBinding_ConcurrentUnboxVsStore(t *testing.T) {
	b := &Bouncer{}
	first := &lapi.Client{}
	second := &lapi.Client{}
	b.storeBinding(&b.lapiBound, first)

	const iterations = 20000
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := range iterations {
			if i%2 == 0 {
				b.storeBinding(&b.lapiBound, first)
			} else {
				b.storeBinding(&b.lapiBound, second)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for range iterations {
			loaded := b.loadedLAPI()
			if loaded != first && loaded != second && loaded != nil {
				t.Errorf("torn or unexpected client pointer %p", loaded)
				return
			}
		}
	}()
	wg.Wait()

	stored := b.lapiBound.Load()
	boxed, ok := stored.(*reclaim.Box)
	if !ok {
		t.Fatalf("stored concrete type %T, want *reclaim.Box", stored)
	}
	if boxed.Value != first && boxed.Value != second {
		t.Fatalf("final Value %v, want first or second client", boxed.Value)
	}
}

// TestStoreBinding_AlwaysStoresNewBox fails if a later publish reuses the prior Box pointer.
func TestStoreBinding_AlwaysStoresNewBox(t *testing.T) {
	b := &Bouncer{}
	var dest atomic.Value
	first := &lapi.Client{}
	second := &lapi.Client{}

	b.storeBinding(&dest, first)
	firstBox := dest.Load().(*reclaim.Box)
	b.storeBinding(&dest, second)
	secondBox := dest.Load().(*reclaim.Box)

	if firstBox == secondBox {
		t.Fatal("later publish must Store a new *reclaim.Box, not mutate the prior one")
	}
	if firstBox.Value != first {
		t.Fatalf("prior Box.Value changed in place: got %v", firstBox.Value)
	}
	if secondBox.Value != second {
		t.Fatalf("new Box.Value=%v, want second", secondBox.Value)
	}
}
