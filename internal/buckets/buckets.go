package buckets

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	KindIP     = "ip"
	KindSess   = "sess"
	KindNet    = "asn_net"
	KindRouter = "asn_router"
)

type Tier struct {
	Max  float64
	Loss float64
}

func (t Tier) Enabled() bool { return t.Max > 0 && t.Loss > 0 }

func (t Tier) ratePerSec() float64 { return t.Loss / 100 * t.Max }

func (t Tier) lifetime() time.Duration {
	if !t.Enabled() {
		return 0
	}

	return time.Duration(100 / t.Loss * float64(time.Second))
}

type Ref struct {
	Kind string
	Key  string
}

type Charge struct {
	Ref
	Add float64
}

type Level struct {
	Ref
	Score   float64
	Percent float64
}

type Store struct {
	client  redis.Cmdable
	prefix  string
	timeout time.Duration

	local *ledger

	now func() time.Time
}

func New(client redis.Cmdable, timeout time.Duration) *Store {
	return &Store{
		client:  client,
		prefix:  "cap:bkt:",
		timeout: timeout,
		local:   newLedger(defaultLocalMax),
		now:     time.Now,
	}
}

func Dial(url string, timeout time.Duration) (*Store, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("buckets: %w", err)
	}

	return New(redis.NewClient(opt), timeout), nil
}

func (s *Store) key(profile string, ref Ref) string {
	return s.prefix + profile + ":" + ref.Kind + ":" + ref.Key
}

func (s *Store) Apply(
	ctx context.Context,
	profile string,
	tiers map[string]Tier,
	charges []Charge,
	reads []Ref,
) ([]Level, error) {
	now := s.now()

	live := make([]Charge, 0, len(charges))

	for _, c := range charges {
		if tiers[c.Kind].Enabled() && c.Add != 0 {
			live = append(live, c)
		}
	}

	refs := refUnion(live, reads, tiers)

	if len(refs) == 0 {
		return nil, nil
	}

	if s.client == nil {
		return s.applyLocal(profile, tiers, live, refs, now), nil
	}

	return s.applyRedis(ctx, profile, tiers, live, refs, now)
}

func refUnion(charges []Charge, reads []Ref, tiers map[string]Tier) []Ref {
	seen := map[Ref]struct{}{}
	out := make([]Ref, 0, len(charges)+len(reads))

	add := func(r Ref) {
		if !tiers[r.Kind].Enabled() || r.Key == "" {
			return
		}

		if _, ok := seen[r]; ok {
			return
		}

		seen[r] = struct{}{}
		out = append(out, r)
	}

	for _, c := range charges {
		add(c.Ref)
	}

	for _, r := range reads {
		add(r)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}

		return out[i].Key < out[j].Key
	})

	return out
}

func (s *Store) applyRedis(
	ctx context.Context,
	profile string,
	tiers map[string]Tier,
	charges []Charge,
	refs []Ref,
	now time.Time,
) ([]Level, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	sums := map[Ref]float64{}

	for _, c := range charges {
		sums[c.Ref] += c.Add
	}

	pipe := s.client.Pipeline()
	stored := make([]func() (float64, error), len(refs))

	for i, ref := range refs {
		tier := tiers[ref.Kind]
		key := s.key(profile, ref)
		delta, charged := sums[ref]

		if charged {
			base := tier.ratePerSec() * epoch(now)
			pipe.SetNX(ctx, key, formatBase(base), tier.lifetime())
			cmd := pipe.IncrByFloat(ctx, key, delta)
			pipe.PExpire(ctx, key, tier.lifetime())
			stored[i] = cmd.Result

			continue
		}

		stored[i] = pipe.Get(ctx, key).Float64
	}

	if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
		return nil, err
	}

	levels := make([]Level, len(refs))
	var fixes []func(redis.Pipeliner)

	for i, ref := range refs {
		tier := tiers[ref.Kind]
		raw, err := stored[i]()
		_, charged := sums[ref]

		if err != nil {
			levels[i] = Level{Ref: ref}

			continue
		}

		effective := raw - tier.ratePerSec()*epoch(now)

		if charged && effective < sums[ref] {
			effective = clamp(sums[ref], 0, tier.Max)
			fixes = append(fixes, fixer(s.key(profile, ref), tier, effective, now))
		} else if effective > tier.Max {
			effective = tier.Max

			if charged {
				fixes = append(fixes, fixer(s.key(profile, ref), tier, tier.Max, now))
			}
		} else if effective < 0 {
			effective = 0
		}

		levels[i] = level(ref, tier, effective)
	}

	if len(fixes) > 0 {
		pipe := s.client.Pipeline()

		for _, fix := range fixes {
			fix(pipe)
		}

		if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
			return nil, err
		}
	}

	return levels, nil
}

func fixer(key string, tier Tier, effective float64, now time.Time) func(redis.Pipeliner) {
	base := tier.ratePerSec()*epoch(now) + effective

	return func(pipe redis.Pipeliner) {
		pipe.Set(context.Background(), key, formatBase(base), tier.lifetime())
	}
}

func level(ref Ref, tier Tier, effective float64) Level {
	out := Level{Ref: ref, Score: effective}

	if tier.Max > 0 {
		out.Percent = effective / tier.Max * 100
	}

	return out
}

func formatBase(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}

	if v > hi {
		return hi
	}

	return v
}

var epochStart = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

func epoch(now time.Time) float64 {
	return now.Sub(epochStart).Seconds()
}

const defaultLocalMax = 100000

type ledger struct {
	mu  sync.Mutex
	max int
	m   map[string]float64
}

func newLedger(max int) *ledger {
	return &ledger{max: max, m: map[string]float64{}}
}

func (s *Store) applyLocal(
	profile string,
	tiers map[string]Tier,
	charges []Charge,
	refs []Ref,
	now time.Time,
) []Level {
	sums := map[Ref]float64{}

	for _, c := range charges {
		sums[c.Ref] += c.Add
	}

	s.local.mu.Lock()
	defer s.local.mu.Unlock()

	levels := make([]Level, len(refs))

	for i, ref := range refs {
		tier := tiers[ref.Kind]
		key := s.key(profile, ref)
		rate := tier.ratePerSec()

		stored, ok := s.local.m[key]
		effective := 0.0

		if ok {
			effective = clamp(stored-rate*epoch(now), 0, tier.Max)
		}

		if delta, charged := sums[ref]; charged {
			effective = clamp(effective+delta, 0, tier.Max)
			s.local.m[key] = effective + rate*epoch(now)
		} else if ok {
			if effective <= 0 {
				delete(s.local.m, key)
			}
		}

		levels[i] = level(ref, tier, effective)
	}

	if len(s.local.m) > s.local.max {
		for key := range s.local.m {
			delete(s.local.m, key)

			if len(s.local.m) <= s.local.max/2 {
				break
			}
		}
	}

	return levels
}

func IPKey(addr string) string {
	if addr == "" {
		return ""
	}

	if strings.Contains(addr, ":") {
		return addr + "/128"
	}

	return addr + "/32"
}
