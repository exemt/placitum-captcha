package buckets

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

var testTiers = map[string]Tier{
	KindIP:   {Max: 100, Loss: 10}, // течёт быстро: удобно двигать часы
	KindSess: {Max: 100, Loss: 10},
}

func testStore(t *testing.T, mr *miniredis.Miniredis) *Store {
	t.Helper()

	s := New(redis.NewClient(&redis.Options{Addr: mr.Addr()}), time.Second)

	return s
}

func at(s *Store, when time.Time) { s.now = func() time.Time { return when } }

func ipCharge(add float64) []Charge {
	return []Charge{{Ref: Ref{Kind: KindIP, Key: "1.2.3.4/32"}, Add: add}}
}

func ipRead() []Ref { return []Ref{{Kind: KindIP, Key: "1.2.3.4/32"}} }

// near -- арифметика на сдвинутых координатах несёт микрошум float64;
// сравнение с допуском честнее равенства.
func near(got, want float64) bool {
	d := got - want

	return d > -0.001 && d < 0.001
}

func pick(t *testing.T, levels []Level, kind string) Level {
	t.Helper()

	for _, l := range levels {
		if l.Kind == kind {
			return l
		}
	}

	t.Fatalf("no level for %s in %+v", kind, levels)

	return Level{}
}

// Заряд виден сразу, потери текут по часам, ниже нуля не бывает.
func TestChargeAndDecay(t *testing.T) {
	mr := miniredis.RunT(t)
	s := testStore(t, mr)
	t0 := time.Now()

	at(s, t0)

	got := pick(t, mustApply(t, s, testTiers, ipCharge(50), nil), KindIP)
	if !near(got.Percent, 50) {
		t.Fatalf("percent %v, want 50", got.Percent)
	}

	// Через 3 секунды при потерях 10%/с осталось 20.
	at(s, t0.Add(3*time.Second))

	got = pick(t, mustApply(t, s, testTiers, nil, ipRead()), KindIP)
	if got.Percent < 19.9 || got.Percent > 20.1 {
		t.Fatalf("percent %v, want ~20", got.Percent)
	}

	// Дно: корзина дотекла до нуля, свежий заряд начинается с чистого листа --
	// даже если ключ пережил собственное дно (срок хранения грубее точного).
	at(s, t0.Add(time.Hour))

	got = pick(t, mustApply(t, s, testTiers, ipCharge(10), nil), KindIP)
	if got.Percent < 9.9 || got.Percent > 10.1 {
		t.Fatalf("percent %v, want ~10: заряд утонул в протухшем минусе", got.Percent)
	}
}

/*
 * Твой сценарий: сто запросов бота растеклись по двадцати экземплярам. Счёт
 * общий, поэтому порог берётся суммой, и первый же запрос после порога -- на
 * каком бы экземпляре он ни приземлился -- видит горячую корзину.
 */
func TestBurstAcrossInstances(t *testing.T) {
	mr := miniredis.RunT(t)
	t0 := time.Now()

	instances := make([]*Store, 20)

	for i := range instances {
		instances[i] = testStore(t, mr)
		at(instances[i], t0)
	}

	crossed := -1

	for i := 0; i < 100; i++ {
		s := instances[i%len(instances)]
		got := pick(t, mustApply(t, s, testTiers, ipCharge(1), nil), KindIP)

		if got.Percent >= 60 {
			crossed = i

			break
		}
	}

	if crossed != 59 {
		t.Fatalf("порог взят на запросе %d, ожидался 59", crossed)
	}

	// Любой другой экземпляр видит то же самое немедленно, без зарядов.
	other := instances[7]
	got := pick(t, mustApply(t, other, testTiers, nil, ipRead()), KindIP)

	if got.Percent < 59.9 {
		t.Fatalf("чужой экземпляр видит %v, ожидалось ~60", got.Percent)
	}
}

// Выше ёмкости счёт не копится: остывание ограничено 100/loss секундами.
func TestCeiling(t *testing.T) {
	mr := miniredis.RunT(t)
	s := testStore(t, mr)
	t0 := time.Now()

	at(s, t0)

	got := pick(t, mustApply(t, s, testTiers, ipCharge(500), nil), KindIP)
	if !near(got.Percent, 100) {
		t.Fatalf("percent %v, want 100", got.Percent)
	}

	// Через 5 секунд -- ~50, а не 450: перелив срезан коррекцией.
	at(s, t0.Add(5*time.Second))

	got = pick(t, mustApply(t, s, testTiers, nil, ipRead()), KindIP)
	if got.Percent < 49 || got.Percent > 51 {
		t.Fatalf("percent %v, want ~50", got.Percent)
	}
}

// Снятие -- отрицательный заряд; -100% ёмкости гарантированно обнуляет.
func TestNegativeCharge(t *testing.T) {
	mr := miniredis.RunT(t)
	s := testStore(t, mr)
	t0 := time.Now()

	at(s, t0)
	mustApply(t, s, testTiers, ipCharge(80), nil)

	got := pick(t, mustApply(t, s, testTiers, ipCharge(-100), nil), KindIP)
	if !near(got.Percent, 0) {
		t.Fatalf("percent %v, want 0", got.Percent)
	}
}

// Без Redis экземпляр считает в своей памяти той же арифметикой.
func TestLocalFallback(t *testing.T) {
	s := New(nil, time.Second)
	t0 := time.Now()

	at(s, t0)

	got := pick(t, mustApply(t, s, testTiers, ipCharge(50), nil), KindIP)
	if got.Percent != 50 {
		t.Fatalf("percent %v, want 50", got.Percent)
	}

	at(s, t0.Add(3*time.Second))

	got = pick(t, mustApply(t, s, testTiers, nil, ipRead()), KindIP)
	if got.Percent < 19.9 || got.Percent > 20.1 {
		t.Fatalf("percent %v, want ~20", got.Percent)
	}
}

// Выключенная корзина не считает и не судит; пустые ключи отбрасываются.
func TestDisabledAndEmpty(t *testing.T) {
	mr := miniredis.RunT(t)
	s := testStore(t, mr)

	tiers := map[string]Tier{KindIP: {}}

	if got := mustApply(t, s, tiers,
		ipCharge(50), ipRead()); len(got) != 0 {
		t.Fatalf("levels %+v, want none", got)
	}

	if got := mustApply(t, s, testTiers,
		[]Charge{{Ref: Ref{Kind: KindIP, Key: ""}, Add: 5}}, nil); len(got) != 0 {
		t.Fatalf("levels %+v, want none", got)
	}
}

/*
 * mustApply -- Apply, у которого отказ обменника валит тест: здесь проверяют
 * арифметику корзин, а поведение при недоступном Redis -- своим тестом.
 */
func mustApply(t *testing.T, s *Store, tiers map[string]Tier,
	charges []Charge, reads []Ref) []Level {

	t.Helper()

	levels, err := s.Apply(context.Background(), "p", tiers, charges, reads)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}

	return levels
}

// Отказ обменника уезжает наружу: уровней, по которым судит лестница, нет.
func TestStoreErrorIsReported(t *testing.T) {
	mr := miniredis.RunT(t)
	s := testStore(t, mr)

	mr.Close()

	if _, err := s.Apply(context.Background(), "p", testTiers, ipCharge(50), nil); err == nil {
		t.Fatal("apply: want an error when the store is down")
	}
}
