package stats

import (
	"sort"
	"sync"
	"sync/atomic"
)

type Counters struct {
	mu sync.Mutex
	m  map[string]*atomic.Int64
}

func New() *Counters {
	return &Counters{m: map[string]*atomic.Int64{}}
}

func (c *Counters) Inc(key string) {
	c.mu.Lock()
	v, ok := c.m[key]

	if !ok {
		v = &atomic.Int64{}
		c.m[key] = v
	}

	c.mu.Unlock()
	v.Add(1)
}

func (c *Counters) Snapshot() map[string]int64 {
	c.mu.Lock()
	defer c.mu.Unlock()

	out := make(map[string]int64, len(c.m))

	for k, v := range c.m {
		if n := v.Load(); n != 0 {
			out[k] = n
		}
	}

	return out
}

func (c *Counters) Pairs() []any {
	snap := c.Snapshot()
	keys := make([]string, 0, len(snap))

	for k := range snap {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	out := make([]any, 0, 2*len(keys))

	for _, k := range keys {
		out = append(out, k, snap[k])
	}

	return out
}
