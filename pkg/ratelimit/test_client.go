package ratelimit

import "fmt"

// NewTestClient returns a Client that charges counter instead of Redis, with the buckets compiled and
// the policy kept as Open keeps them and an incarnation set as Open sets it, so a bouncer binding tells
// it apart from nil. It is not in the reclaim table and has no Redis client: do not Sleep, Wake, or Close it.
func NewTestClient(settings Settings, counter Counter) (*Client, error) {
	buckets, err := NewBucketSet(settings.Buckets, settings.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("ratelimit: buckets: %w", err)
	}
	client := &Client{buckets: buckets, counter: counter, policy: settings.Policy}
	client.incarnation = fmt.Sprintf("%p", client)
	return client, nil
}
