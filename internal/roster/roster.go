package roster

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

var ErrNotFound = errors.New("roster: not found")

type Roster interface {
	Revoked(sid string) bool
	Refresh(ctx context.Context) (int, error)

	Revoke(ctx context.Context, sid string, until time.Time) error
	Burn(ctx context.Context, kind, id string, ttl time.Duration) (bool, error)

	Fail(ctx context.Context, scope string, window time.Duration) (int, error)
	Clear(ctx context.Context, scope string) error
	Lock(ctx context.Context, scope string, d time.Duration) error
	LockedFor(ctx context.Context, scope string) (time.Duration, error)

	Put(ctx context.Context, kind, id string, value []byte, ttl time.Duration) error
	Get(ctx context.Context, kind, id string) ([]byte, error)
	Del(ctx context.Context, kind, id string) error

	Close() error
}

func Watch(ctx context.Context, r Roster, every time.Duration, onError func(error)) {
	if r == nil || every <= 0 {
		return
	}

	tick := time.NewTicker(every)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-tick.C:
			if _, err := r.Refresh(ctx); err != nil && onError != nil {
				onError(err)
			}
		}
	}
}

type Redis struct {
	client  *redis.Client
	prefix  string
	timeout time.Duration

	revoked atomic.Pointer[map[string]struct{}]
}

func NewRedis(url, prefix string, timeout time.Duration) (*Redis, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}

	opt.ReadTimeout = timeout
	opt.WriteTimeout = timeout
	opt.DialTimeout = timeout

	r := &Redis{client: redis.NewClient(opt), prefix: prefix, timeout: timeout}
	empty := map[string]struct{}{}
	r.revoked.Store(&empty)

	return r, nil
}

func (r *Redis) key(parts ...string) string {
	out := r.prefix

	for i, p := range parts {
		if i > 0 {
			out += ":"
		}

		out += p
	}

	return out
}

func (r *Redis) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

	return r.client.Ping(ctx).Err()
}

func (r *Redis) Revoked(sid string) bool {
	set := r.revoked.Load()
	if set == nil {
		return false
	}

	_, ok := (*set)[sid]

	return ok
}

func (r *Redis) Refresh(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	now := time.Now().Unix()

	if err := r.client.ZRemRangeByScore(ctx, r.key("rev"), "-inf",
		itoa(now)).Err(); err != nil {
		return 0, err
	}

	ids, err := r.client.ZRange(ctx, r.key("rev"), 0, -1).Result()
	if err != nil {
		return 0, err
	}

	set := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		set[id] = struct{}{}
	}

	r.revoked.Store(&set)

	return len(set), nil
}

func (r *Redis) Revoke(ctx context.Context, sid string, until time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	pipe := r.client.TxPipeline()
	pipe.ZAdd(ctx, r.key("rev"), redis.Z{Score: float64(until.Unix()), Member: sid})

	_, err := pipe.Exec(ctx)

	return err
}

func (r *Redis) Burn(ctx context.Context, kind, id string, ttl time.Duration) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	return r.client.SetNX(ctx, r.key(kind, id), 1, ttl).Result()
}

func (r *Redis) Fail(ctx context.Context, scope string, window time.Duration) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	key := r.key("fail", scope)

	pipe := r.client.TxPipeline()
	inc := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, window)

	if _, err := pipe.Exec(ctx); err != nil {
		return 0, err
	}

	return int(inc.Val()), nil
}

func (r *Redis) Clear(ctx context.Context, scope string) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	return r.client.Del(ctx, r.key("fail", scope), r.key("lock", scope)).Err()
}

func (r *Redis) Lock(ctx context.Context, scope string, d time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	pipe := r.client.TxPipeline()
	pipe.Set(ctx, r.key("lock", scope), 1, d)
	pipe.Del(ctx, r.key("fail", scope))

	_, err := pipe.Exec(ctx)

	return err
}

func (r *Redis) LockedFor(ctx context.Context, scope string) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	ttl, err := r.client.TTL(ctx, r.key("lock", scope)).Result()
	if err != nil {
		return 0, err
	}

	if ttl <= 0 {
		return 0, nil
	}

	return ttl, nil
}

func (r *Redis) Put(ctx context.Context, kind, id string, value []byte,
	ttl time.Duration) error {

	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	return r.client.Set(ctx, r.key(kind, id), value, ttl).Err()
}

func (r *Redis) Get(ctx context.Context, kind, id string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	out, err := r.client.Get(ctx, r.key(kind, id)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}

	return out, err
}

func (r *Redis) Del(ctx context.Context, kind, id string) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	return r.client.Del(ctx, r.key(kind, id)).Err()
}

func (r *Redis) Close() error { return r.client.Close() }

type Memory struct {
	mu      sync.Mutex
	revoked map[string]time.Time
	burned  map[string]time.Time
	fails   map[string]counter
	locks   map[string]time.Time
	values  map[string]entry
}

type entry struct {
	value []byte
	until time.Time
}

type counter struct {
	n     int
	until time.Time
}

func NewMemory() *Memory {
	return &Memory{
		revoked: map[string]time.Time{},
		burned:  map[string]time.Time{},
		fails:   map[string]counter{},
		locks:   map[string]time.Time{},
		values:  map[string]entry{},
	}
}

func (m *Memory) Revoked(sid string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	until, ok := m.revoked[sid]

	return ok && time.Now().Before(until)
}

func (m *Memory) Refresh(context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()

	for id, until := range m.revoked {
		if now.After(until) {
			delete(m.revoked, id)
		}
	}

	for id, until := range m.burned {
		if now.After(until) {
			delete(m.burned, id)
		}
	}

	for id, e := range m.values {
		if now.After(e.until) {
			delete(m.values, id)
		}
	}

	return len(m.revoked), nil
}

func (m *Memory) Revoke(_ context.Context, sid string, until time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.revoked[sid] = until

	return nil
}

func (m *Memory) Burn(_ context.Context, kind, id string, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := kind + ":" + id
	now := time.Now()

	if until, ok := m.burned[key]; ok && now.Before(until) {
		return false, nil
	}

	m.burned[key] = now.Add(ttl)

	return true, nil
}

func (m *Memory) Fail(_ context.Context, scope string, window time.Duration) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	c := m.fails[scope]

	if c.until.IsZero() || now.After(c.until) {
		c = counter{}
	}

	c.n++
	c.until = now.Add(window)
	m.fails[scope] = c

	return c.n, nil
}

func (m *Memory) Clear(_ context.Context, scope string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.fails, scope)
	delete(m.locks, scope)

	return nil
}

func (m *Memory) Lock(_ context.Context, scope string, d time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.locks[scope] = time.Now().Add(d)
	delete(m.fails, scope)

	return nil
}

func (m *Memory) LockedFor(_ context.Context, scope string) (time.Duration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	until, ok := m.locks[scope]
	if !ok {
		return 0, nil
	}

	left := time.Until(until)
	if left <= 0 {
		delete(m.locks, scope)

		return 0, nil
	}

	return left, nil
}

func (m *Memory) Put(_ context.Context, kind, id string, value []byte,
	ttl time.Duration) error {

	m.mu.Lock()
	defer m.mu.Unlock()

	m.values[kind+":"+id] = entry{value: value, until: time.Now().Add(ttl)}

	return nil
}

func (m *Memory) Get(_ context.Context, kind, id string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	e, ok := m.values[kind+":"+id]
	if !ok || time.Now().After(e.until) {
		delete(m.values, kind+":"+id)

		return nil, ErrNotFound
	}

	return e.value, nil
}

func (m *Memory) Del(_ context.Context, kind, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.values, kind+":"+id)

	return nil
}

func (m *Memory) Close() error { return nil }

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}

	neg := v < 0
	if neg {
		v = -v
	}

	var buf [20]byte
	i := len(buf)

	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}

	if neg {
		i--
		buf[i] = '-'
	}

	return string(buf[i:])
}
