package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Профили из образа обязаны читаться тем же загрузчиком, что и поколение из
// контроллера: опечатка в каталоге ловится здесь, а не на стенде.
func TestBundledProfiles(t *testing.T) {
	dir, err := filepath.Abs(filepath.Join("..", "..", "profiles"))
	if err != nil {
		t.Fatal(err)
	}

	/*
	 * CAPTCHA_PROFILES_DIR -- каталог, напечатанный контроллером: так
	 * проверяют, что renderProfileYaml и этот загрузчик не разъехались.
	 */
	if ext := os.Getenv("CAPTCHA_PROFILES_DIR"); ext != "" {
		if _, err := LoadProfiles(ext, slog.New(slog.NewTextHandler(os.Stderr, nil))); err != nil {
			t.Fatalf("controller-rendered profiles: %v", err)
		}

		return
	}

	store, err := LoadProfiles(dir, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		t.Fatal(err)
	}

	snap := store.Current()

	for _, name := range []string{"default", "login", "observe", ProbeName} {
		if _, ok := snap.Profile(name); !ok {
			t.Fatalf("profile %s missing; have %v", name, snap.Names())
		}
	}

	probe, _ := snap.Profile(ProbeName)
	if probe.Trigger.When != WhenAlways || probe.Mode != ModeEnforce {
		t.Fatalf("probe variant: %+v", probe.Trigger)
	}

	// Области клиренса умерли: кука действует на весь сервер. Прежний
	// scope: profile из старых файлов читается и игнорируется.
	login, _ := snap.Profile("login")
	if login.Clearance.TTL.D() != time.Hour {
		t.Fatalf("login clearance ttl %v", login.Clearance.TTL.D())
	}
}

func TestRejects(t *testing.T) {
	cases := map[string]string{
		"no path in enforce":       "mode: enforce\n",
		"unknown field":            "mode: enforce\npath: /c\nbogus: 1\n",
		"bad when":                 "path: /c\ntrigger: {when: sometimes}\n",
		"page provider unknown":    "path: /c\npages: [{path: /x, provider: turnstile}]\n",
		"fallback equals provider": "path: /c\nprovider: {kind: image}\nfallback: {kind: image}\n",
		"external no secret":       "path: /c\nprovider: {kind: turnstile}\nprovider_config: {turnstile: {sitekey: k}}\n",
		"same cookies":             "path: /c\nclearance: {cookie: waf_cap}\n",
		"image too short":          "path: /c\nprovider: {kind: image, length: 2}\n",

		// Привязка куки: словарь закрыт, а подсеть и адрес -- одна привязка
		// разной строгости и вместе не берутся.
		"bind unknown":     "path: /c\nclearance: {bind: [asn]}\n",
		"bind subnet + ip": "path: /c\nclearance: {bind: [subnet, ip]}\n",

		// Правило prior: послабление требует имени, ужесточение -- нет.
		"prior without from":        "path: /c\ntrigger: {prior: [{accept: [challenge]}]}\n",
		"prior without accept":      "path: /c\ntrigger: {prior: [{from: ip}]}\n",
		"prior unknown verb":        "path: /c\ntrigger: {prior: [{from: ip, accept: [nuke]}]}\n",
		"prior verb of another":     "path: /c\ntrigger: {prior: [{from: auth, accept: [reauth]}]}\n",
		"prior broadcast skip":      "path: /c\ntrigger: {prior: [{from: \"*\", accept: [skip]}]}\n",
		"prior broadcast threshold": "path: /c\ntrigger: {prior: [{from: \"*\", accept: [threshold]}]}\n",
		"prior broadcast note":      "path: /c\ntrigger: {prior: [{from: \"*\", accept: [note]}]}\n",
		"prior broadcast any":       "path: /c\ntrigger: {prior: [{from: \"*\", accept: [\"*\"]}]}\n",

		// Корзины: пороги в процентах, включённая корзина обязана течь,
		// бан требует banned-набора.
		"bucket captcha_at over 100": "path: /c\nbuckets: {ip: {max: 100, loss: 1, captcha_at: 150}}\n",
		"bucket ban below captcha":   "path: /c\nbuckets: {ip: {max: 100, loss: 1, captcha_at: 60, ban_at: 30}}\n",
		"bucket without loss":        "path: /c\nbuckets: {ip: {max: 100}}\n",
		"bucket loss over 100":       "path: /c\nbuckets: {ip: {max: 100, loss: 500}}\n",

		// Правила по событиям: ровно одно действие, просьбы только у
		// bucket_full (HTTP не на волне), запись в набор требует срока.
		"rule unknown on":       "path: /c\nrules: [{on: sneeze, charge: ip, percent: 10}]\n",
		"rule without action":   "path: /c\nrules: [{on: fail}]\n",
		"rule two actions":      "path: /c\nrules: [{on: fail, charge: ip, percent: 10, list: x, ttl: 1h}]\n",
		"rule ask on fail":      "path: /c\nrules: [{on: fail, to: modsec, do: skip}]\n",
		"rule list without ttl": "path: /c\nrules: [{on: fail, list: x}]\n",
		"rule bad write":        "path: /c\nrules: [{on: fail, list: x, ttl: 1h, write: everything}]\n",
		"rule charge over 100":  "path: /c\nrules: [{on: fail, charge: ip, percent: 500}]\n",
		"rule unknown bucket":   "path: /c\nrules: [{on: bucket_full, bucket: pail, list: x, ttl: 1h}]\n",
		"rule bucket on fail":   "path: /c\nrules: [{on: fail, bucket: ip, charge: ip, percent: 10}]\n",

		// Клиренс -- событие волны, но селектор корзины ему не положен, а cid
		// известен только там, где куку выдали или предъявили: у клиента без
		// клиренса куки нет.
		"rule bucket on cleared":   "path: /c\nrules: [{on: cleared, bucket: ip, charge: ip, percent: -10}]\n",
		"rule bucket on uncleared": "path: /c\nrules: [{on: uncleared, bucket: ip, charge: ip, percent: 10}]\n",
		"rule cid on bucket_ban":   "path: /c\nrules: [{on: bucket_ban, list: x, ttl: 1h, write: cid}]\n",
		"rule cid on uncleared":    "path: /c\nrules: [{on: uncleared, list: x, ttl: 1h, write: cid}]\n",

		// Решение лестницы уточняет только события, где оно бывает любым.
		"rule next on cleared": "path: /c\nrules: [{on: cleared, next: allow, charge: ip, percent: -10}]\n",
		"rule next on fail":    "path: /c\nrules: [{on: fail, next: challenge, charge: ip, percent: 10}]\n",
		"rule bad next":        "path: /c\nrules: [{on: uncleared, next: maybe, charge: ip, percent: 10}]\n",
		"rule ttl on skip":         "path: /c\nrules: [{on: cleared, to: vlai, do: skip, ttl: 1h}]\n",

		// Полная форма просьбы: та же отбраковка, что у модуля на проводе.
		"ask unknown verb":         "path: /c\nrules: [{on: cleared, to: vlai, do: nuke}]\n",
		"ask mutate without group": "path: /c\nrules: [{on: cleared, to: rewrite, do: mutate, set: on}]\n",
		"ask mutate without set":   "path: /c\nrules: [{on: cleared, to: rewrite, do: mutate, group: mask}]\n",
		"ask group on skip":        "path: /c\nrules: [{on: cleared, to: vlai, do: skip, group: mask}]\n",
		"ask control without to":   "path: /c\nrules: [{on: cleared, do: off}]\n",
		"ask control on conn":      "path: /c\nrules: [{on: cleared, to: vlai, do: off, apply: conn}]\n",
		"ask audit without set":    "path: /c\nrules: [{on: cleared, do: audit}]\n",
		"ask audit with to":        "path: /c\nrules: [{on: cleared, to: vlai, do: audit, set: on}]\n",
		"ask audit with ttl":       "path: /c\nrules: [{on: cleared, do: audit, set: on, ttl: 1h}]\n",
		"ask archive off objects":  "path: /c\nrules: [{on: cleared, do: archive, set: off, body: {set: on}}]\n",
		"ask archive bad when":     "path: /c\nrules: [{on: cleared, do: archive, set: on, when: [redirect]}]\n",
		"ask mark without marker":  "path: /c\nrules: [{on: cleared, do: mark}]\n",
		"ask marker on skip":       "path: /c\nrules: [{on: cleared, to: vlai, do: skip, marker: x}]\n",
		"ask score with to":        "path: /c\nrules: [{on: cleared, to: vlai, do: score, value: -10}]\n",
		"ask score zero":           "path: /c\nrules: [{on: cleared, do: score, value: 0}]\n",
	}

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			p, err := ParseProfile("x", []byte(raw))
			if err == nil {
				err = p.Validate()
			}

			if err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// Что загрузчик обязан принять: ужесточение от кого угодно, послабление --
// с именем; мёртвые поля старых профилей читаются и игнорируются.
func TestPriorAccepts(t *testing.T) {
	cases := map[string]string{
		"broadcast challenge": "path: /c\ntrigger: {prior: [{from: \"*\", accept: [challenge]}]}\n",
		"named skip":          "path: /c\ntrigger: {prior: [{from: ip, accept: [skip], codes: [IP_ALLOWLIST]}]}\n",
		"named threshold":     "path: /c\ntrigger: {prior: [{from: ip, accept: [threshold]}]}\n",
		"named any verb":      "path: /c\ntrigger: {prior: [{from: action, accept: [\"*\"]}]}\n",
		"buckets":             "path: /c\nbuckets: {ip: {max: 100, loss: 1, captcha_at: 60, ban_at: 90}}\n",

		// Общие пороги старых строк переливаются в корзины без своих.
		"legacy shared thresholds": "path: /c\nbuckets: {captcha_at: 60, ban_at: 90, ip: {max: 100, loss: 1}}\n",
		"event rules": "path: /c\n" +
			"rules:\n" +
			"  - {on: fail, charge: ip, percent: 20}\n" +
			"  - {on: pass, charge: ip, percent: -100}\n" +
			"  - {on: bucket_full, bucket: ip, list: blacklist, write: addr, ttl: 1h}\n" +
			"  - {on: bucket_full, bucket: asn_net, list: blacklist, write: net, ttl: 1h}\n" +
			"  - {on: bucket_full, to: modsec, do: threshold, delta: 100}\n",

		// Клиренс -- событие волны: все просьбы канала, запись cid, заряд.
		"cleared rules": "path: /c\n" +
			"rules:\n" +
			"  - {on: cleared, to: counter, do: note, apply: ip, value: -100, counter: scraper}\n" +
			"  - {on: cleared, to: modsec, do: threshold, delta: -50}\n" +
			"  - {on: cleared, to: vlai, do: skip, code: HUMAN}\n" +
			"  - {on: cleared, to: vlai, do: off}\n" +
			"  - {on: cleared, to: vlai, do: passive, apply: request}\n" +
			"  - {on: cleared, to: rewrite, do: mutate, group: mask, set: off}\n" +
			"  - {on: cleared, do: audit, set: off}\n" +
			"  - {on: cleared, do: archive, set: on, ttl: 1h, when: [allow], body: {set: on, limit: 4096}}\n" +
			"  - {on: cleared, do: mark, marker: human verified}\n" +
			"  - {on: cleared, do: score, value: -30}\n" +
			"  - {on: cleared, list: cap_seen, write: cid, ttl: 1h}\n" +
			"  - {on: cleared, charge: ip, percent: -10}\n",

		// Без клиренса -- тоже событие волны: просьбы соседям дальше по
		// цепочке, запись маршрута, адрес в набор, заряд.
		"uncleared rules": "path: /c\n" +
			"rules:\n" +
			"  - {on: uncleared, to: vlai, do: active}\n" +
			"  - {on: uncleared, to: rewrite, do: mutate, group: prices, set: on, code: NO_CLEARANCE}\n" +
			"  - {on: uncleared, to: modsec, do: threshold, delta: 50}\n" +
			"  - {on: uncleared, do: score, value: 20}\n" +
			"  - {on: uncleared, do: mark, marker: no clearance}\n" +
			"  - {on: uncleared, list: cap_seen, write: addr, ttl: 1h}\n" +
			"  - {on: uncleared, charge: ip, percent: 5}\n" +
			"  - {on: uncleared, next: challenge, charge: ip, percent: 30}\n" +
			"  - {on: uncleared, next: allow, to: rewrite, do: mutate, group: prices, set: on}\n" +
			"  - {on: bucket_captcha, bucket: ip, next: allow, to: rewrite, do: mutate, group: prices, set: on}\n" +
			"  - {on: bucket_ban, next: challenge, list: blacklist, write: addr, ttl: 1h}\n",

		// Старый формат: apply, потолки, reverify и reputation -- одно
		// поколение читаются и игнорируются с предупреждением.
		"legacy fields ignored": "path: /c\n" +
			"trigger: {reverify_at: 90, reverify_after: 10m, prior: [{from: modsec, accept: [note], apply: [ip, asn], max_value: 100}]}\n" +
			"reputation: {ip: {leak: 60/m, hot_at: 300, ceiling: 2000, hot_for: 10m}}\n",
	}

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			p, err := ParseProfile("x", []byte(raw))
			if err != nil {
				t.Fatal(err)
			}

			if err := p.Validate(); err != nil {
				t.Fatal(err)
			}

			if name == "legacy fields ignored" && len(p.deprecations()) == 0 {
				t.Fatal("legacy fields did not surface as deprecated")
			}
		})
	}
}

/*
 * PoW умер: он доказывал вычисление, а не человечность. Старый профиль
 * читается одно поколение: на месте pow встаёт свой запасной (или картинка,
 * если запасного не было), встреча помечается предупреждением.
 */
func TestLegacyPoWMigrates(t *testing.T) {
	t.Run("fallback promoted", func(t *testing.T) {
		p, err := ParseProfile("x", []byte(
			"path: /c\nprovider: {kind: pow, difficulty: 20}\nfallback: {kind: image, length: 6}\n"))
		if err != nil {
			t.Fatal(err)
		}

		if err := p.Validate(); err != nil {
			t.Fatal(err)
		}

		if p.Provider.Kind != ProviderImage || p.Provider.Length != 6 || p.Fallback != nil {
			t.Fatalf("provider %+v, fallback %+v", p.Provider, p.Fallback)
		}

		if len(p.deprecations()) == 0 {
			t.Fatal("pow did not surface as deprecated")
		}
	})

	t.Run("image by default", func(t *testing.T) {
		p, err := ParseProfile("x", []byte("path: /c\nprovider: {kind: pow}\n"))
		if err != nil {
			t.Fatal(err)
		}

		if err := p.Validate(); err != nil {
			t.Fatal(err)
		}

		if p.Provider.Kind != ProviderImage {
			t.Fatalf("provider %+v", p.Provider)
		}
	})
}

func TestRuleFor(t *testing.T) {
	p, err := ParseProfile("x", []byte(`
path: /c
trigger: {when: score, score_at: 60}
pages:
  - {path: /login, match: exact, when: always}
  - {path: /checkout, methods: [POST], when: always, score_at: 10}
  - {path: /api/, when: never}
`))
	if err != nil {
		t.Fatal(err)
	}

	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}

	check := func(method, uri, when string, scoreAt int) {
		t.Helper()

		r := p.RuleFor(method, uri)
		if r.When != when || r.ScoreAt != scoreAt {
			t.Fatalf("%s %s: %+v", method, uri, r)
		}
	}

	// when: score из старых файлов читается как "по корзинам"; счёт фазы
	// больше не триггер, его порог остаётся мёртвым полем.
	check("GET", "/login", WhenAlways, 60)
	check("GET", "/login/", WhenBuckets, 60)
	check("POST", "/checkout/pay", WhenAlways, 10)
	check("GET", "/checkout/pay", WhenBuckets, 60)
	check("GET", "/api/v1", WhenNever, 60)
	check("GET", "/", WhenBuckets, 60)
}

func TestRate(t *testing.T) {
	p, err := ParseProfile("x", []byte("path: /c\nlimits: {issue_per_subnet: 5/s}\n"))
	if err != nil {
		t.Fatal(err)
	}

	if p.Limits.IssuePerSubnet.N != 5 || p.Limits.IssuePerSubnet.Per.Seconds() != 1 {
		t.Fatalf("%+v", p.Limits.IssuePerSubnet)
	}

	if _, err := ParseProfile("x", []byte("limits: {issue_per_subnet: five}\n")); err == nil {
		t.Fatal("bad rate accepted")
	}
}

/*
 * Привязка к адресу -- та же нарезка, только полной длины: bind решает
 * строгость, clearance.subnet остаётся при лимитах.
 */
func TestBindNetBits(t *testing.T) {
	load := func(raw string) *Profile {
		t.Helper()

		p, err := ParseProfile("x", []byte(raw))
		if err != nil {
			t.Fatal(err)
		}

		if err := p.Validate(); err != nil {
			t.Fatal(err)
		}

		return p
	}

	net := load("path: /c\nclearance: {bind: [subnet, ua], subnet: {v4: 24, v6: 64}}\n")
	if !net.BindsNet() || !net.BindsUA() {
		t.Fatalf("subnet binds: %+v", net.Clearance.Bind)
	}

	if v4, v6 := net.NetBits(); v4 != 24 || v6 != 64 {
		t.Fatalf("subnet bits: %d %d", v4, v6)
	}

	ip := load("path: /c\nclearance: {bind: [ip], subnet: {v4: 24, v6: 64}}\n")
	if !ip.BindsNet() || ip.BindsUA() {
		t.Fatalf("ip binds: %+v", ip.Clearance.Bind)
	}

	if v4, v6 := ip.NetBits(); v4 != 32 || v6 != 128 {
		t.Fatalf("ip bits: %d %d", v4, v6)
	}

	// Лимиты страницы нарезку привязки не наследуют.
	if ip.Clearance.Subnet.V4 != 24 || ip.Clearance.Subnet.V6 != 64 {
		t.Fatalf("limits subnet: %+v", ip.Clearance.Subnet)
	}

	none := load("path: /c\nclearance: {bind: [ua]}\n")
	if none.BindsNet() {
		t.Fatalf("ua-only binds net: %+v", none.Clearance.Bind)
	}
}
