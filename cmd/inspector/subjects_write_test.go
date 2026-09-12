package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/exemt/placitum-captcha/internal/buckets"
	"github.com/exemt/placitum-captcha/internal/config"
	"github.com/exemt/placitum-shared/netinfo"
)

/* --- заглушки ------------------------------------------------------------ */

type fakeGeo struct {
	info netinfo.Info
	err  error
	// calls -- сколько раз спрашивали и с каким expand: путь записи обязан
	// ходить в кодер ровно тогда, когда запись этого требует.
	calls  int
	expand []bool
}

func (g *fakeGeo) Resolve(_ context.Context, _ string) (string, string) { return "", "" }

func (g *fakeGeo) Lookup(_ context.Context, _ netip.Addr, expand bool) (netinfo.Info, error) {
	g.calls++
	g.expand = append(g.expand, expand)

	if g.err != nil {
		return netinfo.Info{}, g.err
	}

	return g.info, nil
}

type write struct {
	set    string
	values []string
	ttl    time.Duration
	reason string
}

type fakeLists struct {
	mu     sync.Mutex
	writes []write
	err    error
}

func (l *fakeLists) Add(name, value string, ttl time.Duration, reason string) error {
	return l.AddMany(name, []string{value}, ttl, reason)
}

func (l *fakeLists) AddMany(name string, values []string, ttl time.Duration, reason string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.err != nil {
		return l.err
	}

	l.writes = append(l.writes, write{set: name, values: values, ttl: ttl, reason: reason})

	return nil
}

func prefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

/* Кодер знает адрес: узкий анонс одной системы внутри широкого другой. */
func nestedInfo() netinfo.Info {
	return netinfo.Info{
		Gen: 1,
		Lo:  netip.MustParseAddr("8.8.8.0"), Hi: netip.MustParseAddr("8.8.8.255"),
		Announces: []netinfo.Announce{
			{Prefix: prefix("8.8.8.0/24"), ASN: 15169, Name: "GOOGLE", Effective: true,
				Prefixes: []netip.Prefix{prefix("8.8.4.0/24"), prefix("8.8.8.0/24")}},
			{Prefix: prefix("8.0.0.0/9"), ASN: 3356, Name: "LEVEL3",
				Prefixes: []netip.Prefix{prefix("8.0.0.0/9")}},
		},
	}
}

func banProfile(rules ...config.EventRule) *config.Profile {
	return &config.Profile{
		Name:    "ladder",
		Mode:    "enforce",
		Buckets: config.Buckets{IP: config.BucketTier{Max: 100, Loss: 1, CaptchaAt: 60, BanAt: 100}},
		Rules:   rules,
	}
}

func banRule(list, write string, ttl time.Duration) config.EventRule {
	return config.EventRule{
		On: config.OnBucketBan, Bucket: "ip", List: list, Write: write,
		TTL: config.Duration(ttl), Code: "E2E_BAN",
	}
}

func testHandler(geo *fakeGeo, lists *fakeLists) *handler {
	return &handler{
		log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		resolver: geo,
		lists:    lists,
	}
}

func fullIP() []buckets.Level {
	return []buckets.Level{{Ref: buckets.Ref{Kind: buckets.KindIP, Key: "8.8.8.143"}, Percent: 100}}
}

/* --- тесты --------------------------------------------------------------- */

/*
 * Три яруса одного события: адрес -- из сообщения, анонсы -- все накрывающие,
 * система -- составы всех накрывающих. Каждый ярус -- одна пачка со своим
 * сроком, и все три ложатся на одном запросе.
 */
func TestWriteLadderAddrNetASN(t *testing.T) {
	geo := &fakeGeo{info: nestedInfo()}
	lists := &fakeLists{}
	h := testHandler(geo, lists)

	p := banProfile(
		banRule("ban-ip", config.WriteAddr, 10*time.Second),
		banRule("ban-net", config.WriteNet, 30*time.Second),
		banRule("ban-net-all", config.WriteNetAll, 30*time.Second),
		banRule("ban-asn", config.WriteASN, time.Minute),
	)

	acts, err := h.fireBucketFull(context.Background(), p, subject{ip: "8.8.8.143"}, "8.8.8.143", fullIP(), "")
	if err != nil {
		t.Fatal(err)
	}

	if len(acts) != 0 {
		t.Fatalf("no asks expected: %+v", acts)
	}

	if len(lists.writes) != 4 {
		t.Fatalf("four writes expected: %+v", lists.writes)
	}

	if w := lists.writes[0]; w.set != "ban-ip" || strings.Join(w.values, " ") != "8.8.8.143" || w.ttl != 10*time.Second {
		t.Fatalf("addr tier: %+v", w)
	}

	/* Лайт: только эффективный анонс -- та же сеть, по которой считается корзина. */
	if w := lists.writes[1]; w.set != "ban-net" || strings.Join(w.values, " ") != "8.8.8.0/24" || w.ttl != 30*time.Second {
		t.Fatalf("net tier (light): effective announce only: %+v", w)
	}

	/* Хард: все накрывающие, от узкого к широкому, включая чужую /9. */
	if w := lists.writes[2]; w.set != "ban-net-all" || strings.Join(w.values, " ") != "8.8.8.0/24 8.0.0.0/9" {
		t.Fatalf("net_all tier (hard): all covering announces: %+v", w)
	}

	/* Система эффективного анонса целиком; чужая широкая система не задета. */
	if w := lists.writes[3]; w.set != "ban-asn" || strings.Join(w.values, " ") != "8.8.4.0/24 8.8.8.0/24" || w.ttl != time.Minute {
		t.Fatalf("asn tier: composition of the effective system only: %+v", w)
	}

	for _, w := range lists.writes {
		if w.reason != "E2E_BAN" {
			t.Fatalf("reason: %+v", w)
		}
	}

	/* Кодер спрошен трижды: два раза под анонсы без состава, один -- с ним. */
	if geo.calls != 3 || geo.expand[0] || geo.expand[1] || !geo.expand[2] {
		t.Fatalf("coder calls: %d expand=%v", geo.calls, geo.expand)
	}
}

/*
 * Памяти «уже записано» нет: пока корзина выше порога, каждое срабатывание --
 * запись. Повторы режет сам бан (набор стоит перед капчей), а повторный add у
 * keeper продлевает срок.
 */
func TestWriteEveryFiring(t *testing.T) {
	geo := &fakeGeo{info: nestedInfo()}
	lists := &fakeLists{}
	h := testHandler(geo, lists)

	p := banProfile(banRule("ban-asn", config.WriteASN, time.Hour))

	for i := 0; i < 3; i++ {
		if _, err := h.fireBucketFull(context.Background(), p, subject{}, "8.8.8.143", fullIP(), ""); err != nil {
			t.Fatal(err)
		}
	}

	if len(lists.writes) != 3 {
		t.Fatalf("every firing must write: writes %d", len(lists.writes))
	}
}

/* Молчащий кодер -- error, не пропуск; адрес при этом пишется, он кодера не ждёт. */
func TestWriteGeoUnavailableIsAnError(t *testing.T) {
	geo := &fakeGeo{err: netinfo.ErrUnavailable}
	lists := &fakeLists{}
	h := testHandler(geo, lists)

	p := banProfile(
		banRule("ban-ip", config.WriteAddr, 10*time.Second),
		banRule("ban-net", config.WriteNet, 30*time.Second),
	)

	_, err := h.fireBucketFull(context.Background(), p, subject{}, "8.8.8.143", fullIP(), "")
	if !errors.Is(err, netinfo.ErrUnavailable) {
		t.Fatalf("expected geo unavailable, got %v", err)
	}

	if len(lists.writes) != 1 || lists.writes[0].set != "ban-ip" {
		t.Fatalf("addr tier does not depend on the coder: %+v", lists.writes)
	}

	/*
	 * Кодер ожил -- следующее срабатывание пишет оба яруса: адрес снова
	 * (памяти «уже записано» нет, повтор продлевает срок), подсеть впервые.
	 */
	geo.err = nil
	geo.info = nestedInfo()

	if _, err := h.fireBucketFull(context.Background(), p, subject{}, "8.8.8.143", fullIP(), ""); err != nil {
		t.Fatal(err)
	}

	if len(lists.writes) != 3 || lists.writes[1].set != "ban-ip" || lists.writes[2].set != "ban-net" {
		t.Fatalf("both tiers after recovery: %+v", lists.writes)
	}
}

/* Кодер знает адрес, но системы у него нет: предупреждение, без записи, без ошибки. */
func TestWriteUnknownAddressSkips(t *testing.T) {
	geo := &fakeGeo{info: netinfo.Info{Gen: 1}}
	lists := &fakeLists{}
	h := testHandler(geo, lists)

	p := banProfile(banRule("ban-net", config.WriteNet, 30*time.Second))

	if _, err := h.fireBucketFull(context.Background(), p, subject{}, "198.18.1.1", fullIP(), ""); err != nil {
		t.Fatal(err)
	}

	if len(lists.writes) != 0 {
		t.Fatalf("nothing to write: %+v", lists.writes)
	}
}

/* Неудача keeper -- предупреждение, не ошибка вердикта; следующий запрос пишет снова. */
func TestWriteKeeperFailureRetries(t *testing.T) {
	geo := &fakeGeo{info: nestedInfo()}
	lists := &fakeLists{err: errors.New("keeper unreachable")}
	h := testHandler(geo, lists)

	p := banProfile(banRule("ban-ip", config.WriteAddr, 10*time.Second))

	if _, err := h.fireBucketFull(context.Background(), p, subject{}, "8.8.8.143", fullIP(), ""); err != nil {
		t.Fatalf("keeper failure is not a verdict error: %v", err)
	}

	lists.err = nil

	if _, err := h.fireBucketFull(context.Background(), p, subject{}, "8.8.8.143", fullIP(), ""); err != nil {
		t.Fatal(err)
	}

	if len(lists.writes) != 1 {
		t.Fatalf("retry after keeper failure: %+v", lists.writes)
	}
}

/* Порог не взят -- правила молчат, кодер не спрашивается. */
func TestWriteBelowThreshold(t *testing.T) {
	geo := &fakeGeo{info: nestedInfo()}
	lists := &fakeLists{}
	h := testHandler(geo, lists)

	p := banProfile(banRule("ban-net", config.WriteNet, 30*time.Second))
	levels := []buckets.Level{{Ref: buckets.Ref{Kind: buckets.KindIP, Key: "8.8.8.143"}, Percent: 99}}

	if _, err := h.fireBucketFull(context.Background(), p, subject{}, "8.8.8.143", levels, ""); err != nil {
		t.Fatal(err)
	}

	if len(lists.writes) != 0 || geo.calls != 0 {
		t.Fatalf("below ban_at nothing fires: writes %d, coder %d", len(lists.writes), geo.calls)
	}
}
