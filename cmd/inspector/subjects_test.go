/*
 * Список чтения корзин. Проверяется ровно то, ради чего он сузился: клиент с
 * действующим клиренсом стоит одного ключа вместо четырёх, а всё, что решает
 * лестница и правила бана, при этом остаётся на месте.
 */

package main

import (
	"testing"

	"github.com/exemt/placitum-captcha/internal/buckets"
	"github.com/exemt/placitum-captcha/internal/config"
	"github.com/exemt/placitum-captcha/internal/protocol"
)

func allTiers() map[string]buckets.Tier {
	t := buckets.Tier{Max: 100, Loss: 10}

	return map[string]buckets.Tier{
		buckets.KindIP:     t,
		buckets.KindSess:   t,
		buckets.KindNet:    t,
		buckets.KindRouter: t,
	}
}

func full() subject {
	return subject{
		ip:     "203.0.113.7",
		sess:   "9f86d081884c7d65",
		net:    "203.0.113.0/24",
		router: "64500",
	}
}

func kindsOf(refs []buckets.Ref) []string {
	out := make([]string, 0, len(refs))

	for _, r := range refs {
		out = append(out, r.Kind)
	}

	return out
}

func TestReadsOfWithoutClearanceTakesEveryBucket(t *testing.T) {
	got := kindsOf(readsOf(full(), allTiers(), false))

	if len(got) != 4 {
		t.Fatalf("kinds = %v, want all four buckets", got)
	}
}

// Главная правка: пропущенный клиент стоит одного ключа. Общие корзины его не
// судят, поэтому и читать их незачем.
func TestReadsOfWithClearanceTakesOnlySess(t *testing.T) {
	got := kindsOf(readsOf(full(), allTiers(), true))

	if len(got) != 1 || got[0] != buckets.KindSess {
		t.Fatalf("kinds = %v, want only %q", got, buckets.KindSess)
	}
}

// Выключенная корзина не читается ни в одном из режимов: Max == 0 означает,
// что оператор её не завёл, а не что её надо спросить и получить ноль.
func TestReadsOfSkipsDisabledBuckets(t *testing.T) {
	tiers := allTiers()
	tiers[buckets.KindNet] = buckets.Tier{}
	tiers[buckets.KindSess] = buckets.Tier{}

	if got := kindsOf(readsOf(full(), tiers, false)); len(got) != 2 {
		t.Errorf("kinds = %v, want ip and asn_router only", got)
	}

	// Личной корзины нет -- у пропущенного клиента читать вообще нечего, и
	// поход в Redis не нужен: Apply на пустом наборе его не делает.
	if got := readsOf(full(), tiers, true); len(got) != 0 {
		t.Errorf("refs = %v, want none", got)
	}
}

// Пустой ключ субъекта -- корзина без адреса: клиренса нет, ASN не разрезолвен.
// Спрашивать её нечем.
func TestReadsOfSkipsSubjectsWithoutKey(t *testing.T) {
	s := subject{ip: "203.0.113.7"}

	if got := kindsOf(readsOf(s, allTiers(), false)); len(got) != 1 || got[0] != buckets.KindIP {
		t.Fatalf("kinds = %v, want ip only", got)
	}

	if got := readsOf(s, allTiers(), true); len(got) != 0 {
		t.Errorf("refs = %v, want none: there is no clearance to key sess by", got)
	}
}

/*
 * Заряд не теряется от сужения чтения: refUnion объединяет заряды и чтения,
 * поэтому просьба соседа по оси ip доедет до корзины и у пропущенного клиента.
 * Это свойство держит корректность всей правки, поэтому оно проверяется здесь,
 * а не подразумевается.
 */
func TestNarrowReadsStillChargeGeneralBuckets(t *testing.T) {
	tiers := allTiers()
	s := full()

	charges := []buckets.Charge{{
		Ref: buckets.Ref{Kind: buckets.KindIP, Key: s.ip},
		Add: 5,
	}}

	levels, err := buckets.New(nil, 0).Apply(t.Context(), "p", tiers,
		charges, readsOf(s, tiers, true))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}

	var seen []string
	for _, l := range levels {
		seen = append(seen, l.Kind)
	}

	if len(seen) != 2 {
		t.Fatalf("kinds = %v, want the charged ip bucket next to sess", seen)
	}
}

/*
 * Просьба из правила уезжает в полной форме провода: ось дописана там, где она
 * одна (пустая означала бы сообщение старого образца), а у archive с set on
 * срок и исход -- числом и каноническим списком.
 */
func TestAskOfFillsTheWireForm(t *testing.T) {
	ask := askOf(config.EventRule{Do: protocol.DoChallenge, To: "captcha-2"})

	if ask.Apply != protocol.ApplyRequest {
		t.Fatalf("apply = %q, want request", ask.Apply)
	}

	ask = askOf(config.EventRule{Do: protocol.DoReauth, To: "auth"})

	if ask.Apply != protocol.ApplySession {
		t.Fatalf("apply = %q, want session", ask.Apply)
	}

	ask = askOf(config.EventRule{
		Do: protocol.DoArchive, Set: "on", TTL: config.Duration(3600e9),
		When: []string{"deny", "allow"},
		Body: &protocol.ObjectSpec{Set: "on", Limit: 4096},
	})

	if ask.TTL == nil || *ask.TTL != 3600 {
		t.Fatalf("ttl = %v, want 3600", ask.TTL)
	}

	if len(ask.When) != 2 || ask.When[0] != "allow" || ask.When[1] != "deny" {
		t.Fatalf("when = %v, want canonical [allow deny]", ask.When)
	}

	if ask.Body == nil || ask.Body.Limit != 4096 {
		t.Fatalf("body = %v, want limit 4096", ask.Body)
	}

	ask = askOf(config.EventRule{
		Do: protocol.DoMutate, To: "rewrite", Group: "mask", Set: "off",
	})

	if ask.Group != "mask" || ask.Set != "off" {
		t.Fatalf("mutate = %+v, want group mask set off", ask)
	}
}
