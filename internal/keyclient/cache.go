package keyclient

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/clavis/clavis/internal/subject"
)

// cacheEntry holds a granted key and its policies until expiry.
type cacheEntry struct {
	key      []byte
	policies Policies
	expires  time.Time
}

// Cache stores issued document keys for their TTL, so repeated opens of
// the same document do not hit the Key Server on every call.
type Cache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
	now     func() time.Time
}

// NewCache creates an empty cache.
func NewCache() *Cache {
	return &Cache{
		entries: make(map[string]*cacheEntry),
		now:     time.Now,
	}
}

// Get returns the key and policies for the document if present and valid.
func (c *Cache) Get(uuid string) ([]byte, Policies, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	e, ok := c.entries[uuid]
	if !ok {
		return nil, Policies{}, false
	}
	if !e.expires.After(c.now()) {
		return nil, Policies{}, false
	}
	key := make([]byte, len(e.key))
	copy(key, e.key)
	return key, e.policies, true
}

// Put stores (or extends) the entry.
func (c *Cache) Put(uuid string, key []byte, policies Policies, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	c.entries[uuid] = &cacheEntry{
		key:      keyCopy,
		policies: policies,
		expires:  c.now().Add(ttl),
	}
}

// revoke removes the entry for the document (a revocation was received).
func (c *Cache) revoke(uuid string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, uuid)
}

// Revoke removes the entry for the document. It is the hook that a future
// revocation watcher will use.
func (c *Cache) Revoke(uuid string) {
	c.revoke(uuid)
}

// Getter adapts keyclient.Client to crypto.KeyGetter: it resolves the
// subject from the context, issues a key on a miss and caches it.
type Getter struct {
	client *Client
	cache  *Cache
}

// NewGetter creates the KeyGetter adapter.
func NewGetter(client *Client, cache *Cache) *Getter {
	if cache == nil {
		cache = NewCache()
	}
	return &Getter{client: client, cache: cache}
}

// LoadKey implements crypto.KeyGetter. The subject is taken from the
// context (see subject.WithContext).
func (g *Getter) LoadKey(ctx context.Context, docUUID [16]byte) ([]byte, error) {
	uuid := formatUUID(docUUID)

	if key, _, ok := g.cache.Get(uuid); ok {
		return key, nil
	}

	resp, err := g.client.IssueKey(ctx, IssueRequest{
		DocumentUUID: uuid,
		Subject:      subjectFromContext(ctx),
	})
	if err != nil {
		return nil, fmt.Errorf("issue key for %s: %w", uuid, err)
	}

	key, err := hex.DecodeString(resp.Key)
	if err != nil {
		return nil, fmt.Errorf("decode key for %s: %w", uuid, err)
	}

	ttl := time.Duration(resp.TTLSeconds) * time.Second
	if ttl <= 0 {
		// A non-positive TTL means the key must not be cached.
		return key, nil
	}
	g.cache.Put(uuid, key, resp.Policies, ttl)
	return key, nil
}

// PoliciesCached returns the cached policies for the document, if any.
// It is used by higher layers (e.g. the interceptor) to enforce them.
func (g *Getter) PoliciesCached(docUUID [16]byte) (Policies, bool) {
	_, p, ok := g.cache.Get(formatUUID(docUUID))
	return p, ok
}

// Cache exposes the internal cache (e.g. for a revocation watcher).
func (g *Getter) Cache() *Cache { return g.cache }

// subjectFromContext extracts the process identity from the context,
// falling back to an empty subject when none is attached.
func subjectFromContext(ctx context.Context) Subject {
	if s, ok := subject.FromContext(ctx); ok {
		return FromInfo(s)
	}
	return Subject{}
}

func formatUUID(u [16]byte) string {
	// Matches crypto.UUIDString: 8-4-4-4-12 with lowercase hex.
	const hexDigits = "0123456789abcdef"
	var out [36]byte
	idx := 0
	for i, b := range u {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out[idx] = '-'
			idx++
		}
		out[idx] = hexDigits[b>>4]
		idx++
		out[idx] = hexDigits[b&0x0f]
		idx++
	}
	return string(out[:])
}
