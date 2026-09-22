// Package instance is the process-wide LAPI and AppSec slot tables.
// Bouncers subscribe by instance name; owners Publish clients. Fan-out is
// Yaegi-safe atomic.Value, not atomic.Pointer[T] or callbacks.
package instance

import (
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
)

const (
	// LegLAPI is the LAPI slot table key.
	LegLAPI = "lapi"
	// LegAppSec is the AppSec slot table key.
	LegAppSec = "appsec"
	// MsgTaken is the INFO line when two owners claim the same instance name.
	MsgTaken = "crowdsec instance name taken"
	// MsgBound is the DEBUG line when a bouncer subscribes to a slot.
	MsgBound = "crowdsec bouncer bound"
	// MsgUnbound is the DEBUG line when a bouncer unsubscribes from a slot.
	MsgUnbound = "crowdsec bouncer unbound"
)

// PublishAttempt is one leg this constructor wants to publish under the slot mutex.
type PublishAttempt struct {
	Leg          string
	InstanceName string
	Publisher    string
	Client       any
	Empty        any // typed-nil of Client; first atomic.Value Store must keep this type
	Incarnation  string
	StreamScopes []string
	Log          *slog.Logger
}

// Subscriber is one bouncing middleware's atomic.Value for a named slot.
type Subscriber struct {
	Value        *atomic.Value
	TraefikName  string
	Log          *slog.Logger
	HeaderScopes map[string]string
}

type slot struct {
	current      any
	empty        any
	publisher    string
	incarnation  string
	streamScopes []string
	subscribers  []Subscriber
}

type table struct {
	slots map[string]*slot
}

type registry struct {
	mu     sync.Mutex
	lapi   table
	appsec table
}

//nolint:gochecknoglobals // process-wide LAPI and AppSec slot tables for Traefik reload
var process = newRegistry()

func newRegistry() *registry {
	return &registry{
		lapi:   table{slots: make(map[string]*slot)},
		appsec: table{slots: make(map[string]*slot)},
	}
}

func (r *registry) tableFor(leg string) *table {
	if leg == LegAppSec {
		return &r.appsec
	}
	return &r.lapi
}

// ResetForTest drops both slot tables. Tests only. Mutates in place so
// concurrent packages do not race on the process pointer.
func ResetForTest() {
	process.mu.Lock()
	defer process.mu.Unlock()
	process.lapi = table{slots: make(map[string]*slot)}
	process.appsec = table{slots: make(map[string]*slot)}
}

// PublishAll publishes every attempt under one mutex. A rejected name unpublishes
// slots this attempt already wrote before the mutex is released.
func PublishAll(attempts []PublishAttempt) error {
	process.mu.Lock()
	defer process.mu.Unlock()
	written := make([]PublishAttempt, 0, len(attempts))
	for _, attempt := range attempts {
		if err := publishLocked(attempt); err != nil {
			for _, prior := range written {
				unpublishLocked(prior.Leg, prior.InstanceName, prior.Client, prior.Publisher)
			}
			return err
		}
		written = append(written, attempt)
	}
	return nil
}

func publishLocked(attempt PublishAttempt) error {
	if attempt.InstanceName == "" || attempt.Client == nil {
		return nil
	}
	slots := process.tableFor(attempt.Leg).slots
	named := slots[attempt.InstanceName]
	if named != nil && named.publisher != "" && named.publisher != attempt.Publisher {
		if attempt.Log != nil {
			attempt.Log.Error(MsgTaken,
				"leg", attempt.Leg,
				"instanceName", attempt.InstanceName,
				"publisher", named.publisher,
				"rejected", attempt.Publisher,
			)
		}
		return fmt.Errorf("crowdsec instance name %q on leg %s is held by %q; release it before %q can publish",
			attempt.InstanceName, attempt.Leg, named.publisher, attempt.Publisher)
	}
	// One publisher holds one name. A rename must drop the previous slot so
	// subscribers of the old name unbind without waiting for Close.
	if attempt.Publisher != "" {
		for otherName, other := range slots {
			if otherName == attempt.InstanceName || other.publisher != attempt.Publisher {
				continue
			}
			clearSlot(other, attempt.Leg, otherName)
		}
	}
	if named == nil {
		named = &slot{}
		slots[attempt.InstanceName] = named
	}
	if named.empty == nil && attempt.Empty != nil {
		named.empty = attempt.Empty
	}
	named.current = attempt.Client
	named.publisher = attempt.Publisher
	named.incarnation = attempt.Incarnation
	named.streamScopes = attempt.StreamScopes
	fanout(named, attempt.Client, attempt.Leg, attempt.InstanceName)
	return nil
}

// Subscribe appends the bouncer atomic and copies current (typed nil when empty).
// It never waits for a publisher.
func Subscribe(leg, instanceName string, sub Subscriber) {
	if instanceName == "" || sub.Value == nil {
		return
	}
	process.mu.Lock()
	defer process.mu.Unlock()
	slots := process.tableFor(leg).slots
	named := slots[instanceName]
	if named == nil {
		named = &slot{}
		slots[instanceName] = named
	}
	named.subscribers = append(named.subscribers, sub)
	current := named.current
	if isNilClient(current) {
		storeValue(named, sub, named.empty, leg, instanceName, true)
		return
	}
	storeValue(named, sub, current, leg, instanceName, false)
}

// Unsubscribe removes this atomic from the named slot. It does not Close the client.
func Unsubscribe(leg, instanceName string, value *atomic.Value) {
	if instanceName == "" || value == nil {
		return
	}
	process.mu.Lock()
	defer process.mu.Unlock()
	named := process.tableFor(leg).slots[instanceName]
	if named == nil {
		return
	}
	kept := named.subscribers[:0]
	for _, sub := range named.subscribers {
		if sub.Value != value {
			kept = append(kept, sub)
		}
	}
	named.subscribers = kept
}

// Unpublish clears the slot when this publisher still holds this client (rename Wake).
func Unpublish(leg, instanceName string, client any, publisher string) {
	process.mu.Lock()
	defer process.mu.Unlock()
	unpublishLocked(leg, instanceName, client, publisher)
}

func unpublishLocked(leg, instanceName string, client any, publisher string) {
	named := process.tableFor(leg).slots[instanceName]
	if named == nil {
		return
	}
	if named.publisher != publisher || !sameClient(named.current, client) {
		return
	}
	clearSlot(named, leg, instanceName)
}

// Clear is generation-aware grace Close: only slots still pointing at dying
// whose recorded publisher matches.
func Clear(leg string, dying any, publisher string) {
	if isNilClient(dying) {
		return
	}
	process.mu.Lock()
	defer process.mu.Unlock()
	for instanceName, named := range process.tableFor(leg).slots {
		if named.publisher != publisher || !sameClient(named.current, dying) {
			continue
		}
		clearSlot(named, leg, instanceName)
	}
}

func clearSlot(named *slot, leg, instanceName string) {
	empty := named.empty
	named.current = empty
	named.publisher = ""
	fanout(named, empty, leg, instanceName)
}

func fanout(named *slot, client any, leg, instanceName string) {
	for _, sub := range named.subscribers {
		storeValue(named, sub, client, leg, instanceName, false)
	}
}

func storeValue(named *slot, sub Subscriber, client any, leg, instanceName string, subscribeEmpty bool) {
	toStore := client
	if isNilClient(client) && named.empty == nil {
		if subscribeEmpty && sub.Log != nil {
			sub.Log.Info(MsgUnbound,
				"traefikName", sub.TraefikName,
				"leg", leg,
				"instanceName", instanceName,
				"incarnation", named.incarnation,
			)
		}
		return
	}
	if isNilClient(client) {
		toStore = named.empty
	}
	prev := sub.Value.Load()
	changed := !sameClient(prev, toStore)
	if !changed && !subscribeEmpty {
		return
	}
	sub.Value.Store(toStore)
	if sub.Log == nil {
		return
	}
	incarnation := named.incarnation
	if isNilClient(client) {
		sub.Log.Info(MsgUnbound,
			"traefikName", sub.TraefikName,
			"leg", leg,
			"instanceName", instanceName,
			"incarnation", incarnation,
		)
		return
	}
	sub.Log.Info(MsgBound,
		"traefikName", sub.TraefikName,
		"leg", leg,
		"instanceName", instanceName,
		"incarnation", incarnation,
	)
	warnMissingScopes(sub, named.streamScopes)
}

func warnMissingScopes(sub Subscriber, streamScopes []string) {
	if sub.Log == nil || len(sub.HeaderScopes) == 0 {
		return
	}
	missing := decisionscope.MissingStreamScopes(sub.HeaderScopes, streamScopes)
	if len(missing) == 0 {
		return
	}
	sub.Log.Warn("crowdsec bouncer stream scopes missing",
		"traefikName", sub.TraefikName,
		"missing", strings.Join(missing, ","),
	)
}

func isNilClient(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	return reflected.Kind() == reflect.Ptr && reflected.IsNil()
}

func sameClient(left, right any) bool {
	if isNilClient(left) && isNilClient(right) {
		return true
	}
	if isNilClient(left) || isNilClient(right) {
		return false
	}
	return left == right
}
