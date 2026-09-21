// Package instance is the process table of named LAPI and AppSec clients.
package instance

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/appsec"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
)

// table holds named *lapi.Client and *appsec.Client values in atomic.Value (Yaegi).
type table struct {
	mu     sync.Mutex
	lapi   map[string]*atomic.Value
	appsec map[string]*atomic.Value
}

var (
	defaultMu sync.Mutex
	defaultT  *table
)

func defaultTable() *table {
	defaultMu.Lock()
	defer defaultMu.Unlock()
	if defaultT == nil {
		defaultT = &table{
			lapi:   map[string]*atomic.Value{},
			appsec: map[string]*atomic.Value{},
		}
	}
	return defaultT
}

func slot(m map[string]*atomic.Value, name string) *atomic.Value {
	if held, ok := m[name]; ok {
		return held
	}
	held := &atomic.Value{}
	m[name] = held
	return held
}

// PublishLAPI stores client under name. A different *Client already published fails.
func PublishLAPI(name string, client *lapi.Client) error {
	if name == "" || client == nil {
		return fmt.Errorf("lapi instance %q: publish needs a name and a client", name)
	}
	t := defaultTable()
	t.mu.Lock()
	defer t.mu.Unlock()
	held := slot(t.lapi, name)
	if current, ok := held.Load().(*lapi.Client); ok && current != nil && current != client && !current.Closed() {
		return fmt.Errorf("lapi instance %q: already published for a different client", name)
	}
	held.Store(client)
	return nil
}

// PeekLAPI returns the published LAPI client, or nil.
func PeekLAPI(name string) *lapi.Client {
	if name == "" {
		return nil
	}
	t := defaultTable()
	t.mu.Lock()
	held := t.lapi[name]
	t.mu.Unlock()
	if held == nil {
		return nil
	}
	client, _ := held.Load().(*lapi.Client)
	return client
}

// PublishAppsec stores client under name. A different *Client already published fails.
func PublishAppsec(name string, client *appsec.Client) error {
	if name == "" || client == nil {
		return fmt.Errorf("appsec instance %q: publish needs a name and a client", name)
	}
	t := defaultTable()
	t.mu.Lock()
	defer t.mu.Unlock()
	held := slot(t.appsec, name)
	if current, ok := held.Load().(*appsec.Client); ok && current != nil && current != client && !current.Closed() {
		return fmt.Errorf("appsec instance %q: already published for a different client", name)
	}
	held.Store(client)
	return nil
}

// PeekAppsec returns the published AppSec client, or nil.
func PeekAppsec(name string) *appsec.Client {
	if name == "" {
		return nil
	}
	t := defaultTable()
	t.mu.Lock()
	held := t.appsec[name]
	t.mu.Unlock()
	if held == nil {
		return nil
	}
	client, _ := held.Load().(*appsec.Client)
	return client
}

// ResetForTest clears the process table. Tests only.
func ResetForTest() {
	defaultMu.Lock()
	defer defaultMu.Unlock()
	defaultT = &table{
		lapi:   map[string]*atomic.Value{},
		appsec: map[string]*atomic.Value{},
	}
}
