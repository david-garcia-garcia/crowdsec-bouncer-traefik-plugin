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

// Leg names used in logs and as table keys.
const (
	LegLAPI    = "lapi"
	LegAppSec  = "appsec"
	MsgTaken   = "crowdsec instance name taken"
	MsgBound   = "crowdsec bouncer bound"
	MsgUnbound = "crowdsec bouncer unbound"
)

// Identified is a published client that can name its incarnation for lifecycle logs.
type Identified interface {
	Incarnation() string
}

// PublishAttempt is one leg this constructor wants to publish under the slot mutex.
type PublishAttempt struct {
	Leg          string
	InstanceName string
	Publisher    string
	Client       any
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
	current     any
	empty       any
	publisher   string
	subscribers []Subscriber
}

type table struct {
	slots map[string]*slot
}

type registry struct {
	mu     sync.Mutex
	lapi   table
	appsec table
}

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

// ResetForTest drops both slot tables. Tests only.
func ResetForTest() {
	process = newRegistry()
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
	if named == nil {
		named = &slot{}
		slots[attempt.InstanceName] = named
	}
	if named.empty == nil {
		named.empty = typedNil(attempt.Client)
	}
	named.current = attempt.Client
	named.publisher = attempt.Publisher
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
		empty := named.empty
		if empty == nil {
			empty = current
		}
		storeValue(sub, empty, leg, instanceName, true)
		return
	}
	storeValue(sub, current, leg, instanceName, false)
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
	if empty == nil {
		empty = typedNil(named.current)
		named.empty = empty
	}
	named.current = empty
	named.publisher = ""
	fanout(named, empty, leg, instanceName)
}

func fanout(named *slot, client any, leg, instanceName string) {
	for _, sub := range named.subscribers {
		storeValue(sub, client, leg, instanceName, false)
	}
}

func storeValue(sub Subscriber, client any, leg, instanceName string, subscribeEmpty bool) {
	toStore := client
	if isNilClient(client) {
		if prev := sub.Value.Load(); !isNilClient(prev) {
			toStore = typedNil(prev)
		} else if prev != nil {
			toStore = typedNil(prev)
		} else {
			return
		}
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
	incarnation := incarnationOf(client)
	if isNilClient(client) {
		if incarnation == "" {
			incarnation = incarnationOf(prev)
		}
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
	warnMissingScopes(sub, client)
}

type scopeListed interface {
	StreamScopes() []string
}

func warnMissingScopes(sub Subscriber, client any) {
	if sub.Log == nil || len(sub.HeaderScopes) == 0 {
		return
	}
	listed, ok := client.(scopeListed)
	if !ok {
		return
	}
	missing := decisionscope.MissingStreamScopes(sub.HeaderScopes, listed.StreamScopes())
	if len(missing) == 0 {
		return
	}
	sub.Log.Warn("crowdsec bouncer stream scopes missing",
		"traefikName", sub.TraefikName,
		"missing", strings.Join(missing, ","),
	)
}

func incarnationOf(value any) string {
	if isNilClient(value) {
		return ""
	}
	identified, ok := value.(Identified)
	if !ok {
		return ""
	}
	return identified.Incarnation()
}

func typedNil(value any) any {
	if value == nil {
		return nil
	}
	valueType := reflect.TypeOf(value)
	if valueType == nil || valueType.Kind() != reflect.Ptr {
		return nil
	}
	return reflect.Zero(valueType).Interface()
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
