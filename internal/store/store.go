package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/exemt/placitum-captcha/internal/protocol"
)

const (
	UnavailableNoStore  = "store_unconfigured"
	UnavailableError    = "store_error"
	UnavailableDriver   = "unknown_driver"
	UnavailableNotFound = "store_miss"
)

var ErrUnknownDriver = errors.New("unknown store driver")

type Redis struct {
	client  *redis.Client
	timeout time.Duration
}

func NewRedis(url string, timeout time.Duration) (*Redis, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}

	opt.ReadTimeout = timeout
	opt.WriteTimeout = timeout
	opt.DialTimeout = timeout

	return &Redis{client: redis.NewClient(opt), timeout: timeout}, nil
}

func (s *Redis) Get(ctx context.Context, driver, key string) ([]byte, error) {
	if driver != "redis" {
		return nil, ErrUnknownDriver
	}

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	return s.client.Get(ctx, key).Bytes()
}

func (s *Redis) Put(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	return s.client.Set(ctx, key, value, ttl).Err()
}

func (s *Redis) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

	return s.client.Ping(ctx).Err()
}

func (s *Redis) Close() error { return s.client.Close() }

func Headers(ctx context.Context, s *Redis, loc *protocol.Locator) (
	[]protocol.Header, string, bool) {

	switch {
	case loc == nil:
		return nil, "", false

	case loc.Unavailable != "":
		return nil, loc.Unavailable, false

	case loc.Driver == "":
		return nil, "", false
	}

	if s == nil {
		return nil, UnavailableNoStore, true
	}

	raw, err := s.Get(ctx, loc.Driver, loc.Key)

	switch {
	case errors.Is(err, redis.Nil):
		return nil, UnavailableNotFound, true

	case errors.Is(err, ErrUnknownDriver):
		return nil, UnavailableDriver, true

	case err != nil:
		return nil, UnavailableError, true
	}

	var pairs []protocol.Header
	if err := json.Unmarshal(raw, &pairs); err != nil {
		return nil, UnavailableError, true
	}

	return pairs, "", false
}

func Pair(ctx context.Context, s *Redis, hdr, args *protocol.Locator) (
	[]protocol.Header, string, string, bool) {

	if s == nil || hdr == nil || args == nil ||
		hdr.Driver != "redis" || args.Driver != "redis" ||
		hdr.Unavailable != "" || args.Unavailable != "" {
		pairs, why, fault := Headers(ctx, s, hdr)

		return pairs, argsOf(ctx, s, args), why, fault
	}

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	vals, err := s.client.MGet(ctx, hdr.Key, args.Key).Result()
	if err != nil || len(vals) != 2 {
		return nil, "", UnavailableError, true
	}

	raw, ok := vals[0].(string)
	if !ok {
		return nil, str(vals[1]), UnavailableNotFound, true
	}

	var pairs []protocol.Header
	if err := json.Unmarshal([]byte(raw), &pairs); err != nil {
		return nil, str(vals[1]), UnavailableError, true
	}

	return pairs, str(vals[1]), "", false
}

func argsOf(ctx context.Context, s *Redis, loc *protocol.Locator) string {
	if s == nil || loc == nil || loc.Driver == "" || loc.Unavailable != "" {
		return ""
	}

	raw, err := s.Get(ctx, loc.Driver, loc.Key)
	if err != nil {
		return ""
	}

	return string(raw)
}

func str(v any) string {
	s, _ := v.(string)

	return s
}

func Value(pairs []protocol.Header, name string) string {
	for _, h := range pairs {
		if strings.EqualFold(h.Name(), name) {
			return h.Value()
		}
	}

	return ""
}

func Cookie(pairs []protocol.Header, name string) string {
	for _, h := range pairs {
		if !strings.EqualFold(h.Name(), "cookie") {
			continue
		}

		if v := cookieFrom(h.Value(), name); v != "" {
			return v
		}
	}

	return ""
}

func cookieFrom(line, name string) string {
	for len(line) > 0 {
		var part string

		if i := strings.IndexByte(line, ';'); i >= 0 {
			part, line = line[:i], line[i+1:]
		} else {
			part, line = line, ""
		}

		part = strings.TrimSpace(part)

		key, value, ok := strings.Cut(part, "=")
		if !ok || strings.TrimSpace(key) != name {
			continue
		}

		return strings.Trim(strings.TrimSpace(value), `"`)
	}

	return ""
}
