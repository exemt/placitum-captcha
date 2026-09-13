package decide

import (
	"strings"
	"testing"
	"time"

	"github.com/exemt/placitum-captcha/internal/buckets"
	"github.com/exemt/placitum-captcha/internal/config"
	"github.com/exemt/placitum-captcha/internal/protocol"
	"github.com/exemt/placitum-captcha/internal/token"
)

const profileYAML = `
mode: enforce
path: /waf/captcha
trigger:
  prior:
    - from: "*"
      accept: [challenge]
    - from: ip
      accept: [challenge, skip, threshold]
    - from: modsec
      accept: [note]
    - from: action
      accept: ["*"]
buckets:
  ip:        { max: 100,  loss: 1, captcha_at: 60, ban_at: 90 }
  sess:      { max: 100,  loss: 1, captcha_at: 60 }
  asn_net:   { max: 300,  loss: 1, captcha_at: 60 }
  asn_router: { max: 1000, loss: 1, captcha_at: 60 }
pages:
  - path: /login
    match: exact
    when: always
  - path: /api/
    when: never
gate: {}
provider:
  kind: image
`

// prior -- одна запись фазы запроса от названного соседа. Записей пассивного
// отправителя здесь нет и быть не может: модуль их в prior не кладёт.
func prior(from string, actions ...protocol.Action) []protocol.PriorVerdict {
	return []protocol.PriorVerdict{{
		Phase:     protocol.PhaseRequest,
		Inspector: from,
		Verdict:   protocol.VerdictAllow,
		Actions:   actions,
	}}
}

// act -- действие с явной осью: модуль её пишет всегда.
func act(do, axis string) protocol.Action {
	return protocol.Action{Do: do, Apply: axis}
}

type noRevoke struct{ ids map[string]bool }

func (n noRevoke) Revoked(id string) bool { return n.ids[id] }

// clearedAll -- зеркало, в котором живы все клиренсы: профили без списка его не спрашивают.
type clearedAll struct{}

func (clearedAll) Contains(_, _ string) (bool, bool) { return true, true }

// cleared -- зеркало списка для тестов истины списка.
type cleared struct {
	ready bool
	ids   map[string]bool
}

func (c cleared) Contains(_, jti string) (ok, ready bool) { return c.ids[jti], c.ready }

func fixture(t *testing.T) (*config.Profile, *token.Key) {
	t.Helper()

	p, err := config.ParseProfile("default", []byte(profileYAML))
	if err != nil {
		t.Fatal(err)
	}

	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}

	key, err := token.NewKey([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}

	return p, key
}

func nav(p *config.Profile) Input {
	return Input{
		Profile:   p,
		Ask:       p.Name,
		Method:    "GET",
		URI:       "/cart",
		ClientIP:  "203.0.113.42",
		UserAgent: "Mozilla/5.0",
		Accept:    "text/html",
		Now:       time.Now(),
	}
}

// hot -- заполненная корзина адреса: то, что раньше делал счёт фазы.
func hot(in *Input) {
	in.Levels = map[string]float64{buckets.KindIP: 60}
}

// ask разбирает просьбы так же, как это делает обработчик до похода в корзины.
func ask(p *config.Profile, from string, actions ...protocol.Action) Asked {
	return PriorAsk(prior(from, actions...), p)
}

func clearance(t *testing.T, p *config.Profile, key *token.Key, in Input, issued time.Time) string {
	t.Helper()

	c := &token.Clearance{
		JTI:      "jti-1",
		CID:      "cid-1",
		Issued:   issued.Unix(),
		Expiry:   issued.Add(p.Clearance.TTL.D()).Unix(),
		Profile:  p.Name,
		Provider: "image",
		Net:      token.Subnet(in.ClientIP, 24, 64),
		UA:       token.Fingerprint(in.UserAgent),
	}

	raw, err := key.SealClearance(c)
	if err != nil {
		t.Fatal(err)
	}

	return raw
}

func TestLadder(t *testing.T) {
	p, key := fixture(t)

	cases := []struct {
		name    string
		mutate  func(*Input)
		verdict string
		code    string
		trigger string
	}{
		{"cold buckets, no cookie", func(in *Input) {
			in.Levels = map[string]float64{buckets.KindIP: 30}
		}, protocol.VerdictAllow, CodeNotRequired, ""},
		{"page always", func(in *Input) { in.URI = "/login" },
			protocol.VerdictRedirect, CodeRequired, TriggerAlways},
		{"page never beats a hot bucket", func(in *Input) { in.URI = "/api/x"; hot(in) },
			protocol.VerdictAllow, CodeNotRequired, ""},
		{"prior wants captcha", func(in *Input) {
			in.Asked = ask(p, "ip", act(protocol.DoChallenge, protocol.ApplyRequest))
		}, protocol.VerdictRedirect, CodeRequired, TriggerPrior},

		{"neighbour numbers do not trigger", func(in *Input) {
			// score соседа правилу недоступен: внутренняя шкала соседа.
			in.Asked = PriorAsk([]protocol.PriorVerdict{{Phase: "request",
				Inspector: "repu", Verdict: "score", Score: 80}}, p)
		}, protocol.VerdictAllow, CodeNotRequired, ""},

		{"prior from response phase ignored", func(in *Input) {
			v := prior("ip", act(protocol.DoChallenge, protocol.ApplyRequest))
			v[0].Phase = "response"
			in.Asked = PriorAsk(v, p)
		}, protocol.VerdictAllow, CodeNotRequired, ""},

		{"page never beats a challenge request", func(in *Input) {
			/*
			 * Просьба соседа рекомендательная: где оператор сказал "здесь
			 * никогда", проверки не будет ни от кого. Рычага, который снимал
			 * бы это решение, на проводе нет.
			 */
			in.URI = "/api/x"
			in.Asked = ask(p, "ip", act(protocol.DoChallenge, protocol.ApplyRequest))
		}, protocol.VerdictAllow, CodeNotRequired, ""},

		{"skip beats a hot bucket", func(in *Input) {
			hot(in)
			in.Asked = ask(p, "ip", act(protocol.DoSkip, protocol.ApplyRequest))
		}, protocol.VerdictAllow, CodeNotRequired, ""},

		{"threshold is dead: no scale, no trigger", func(in *Input) {
			// Счёта фазы у капчи больше нет -- глаголу нечего двигать.
			in.Asked = ask(p, "ip", protocol.Action{
				Do: protocol.DoThreshold, Apply: protocol.ApplyRequest, Delta: 900})
		}, protocol.VerdictAllow, CodeNotRequired, ""},

		{"note never triggers the widget by itself", func(in *Input) {
			in.Asked = ask(p, "modsec", protocol.Action{
				Do: protocol.DoNote, Apply: protocol.ApplyIP, Value: 90})
		}, protocol.VerdictAllow, CodeNotRequired, ""},

		{"skip from a sender without a rule ignored", func(in *Input) {
			hot(in)
			in.Asked = ask(p, "modsec", act(protocol.DoSkip, protocol.ApplyRequest))
		}, protocol.VerdictRedirect, CodeRequired, TriggerHot},

		{"post gets deny with ticket", func(in *Input) { hot(in); in.Method = "POST" },
			protocol.VerdictDeny, CodeRequired, TriggerHot},
		{"xhr gets deny", func(in *Input) { hot(in); in.Accept = "application/json" },
			protocol.VerdictDeny, CodeRequired, TriggerHot},
		// favicon.ico и прочие подзапросы: страницей их не покажут, а редирект
		// перевыпустил бы билет открытой страницы виджета.
		{"subresource gets deny", func(in *Input) {
			hot(in)
			in.Accept = "image/avif,image/webp,*/*;q=0.8"
			in.SecFetchDest = "image"
		}, protocol.VerdictDeny, CodeRequired, TriggerHot},
		{"page fetch gets deny", func(in *Input) {
			hot(in)
			in.Accept = "*/*"
			in.SecFetchDest = "empty"
		}, protocol.VerdictDeny, CodeRequired, TriggerHot},
		{"browser navigation redirects", func(in *Input) {
			hot(in)
			in.Accept = "text/html,*/*;q=0.8"
			in.SecFetchDest = "document"
		}, protocol.VerdictRedirect, CodeRequired, TriggerHot},
		// Обычный HTTP: Sec-Fetch-* браузер не шлёт. Переход узнаётся по
		// Upgrade-Insecure-Requests, favicon и fetch фронтенда -- подзапросы.
		{"plain http favicon gets deny", func(in *Input) {
			hot(in)
			in.Accept = "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"
		}, protocol.VerdictDeny, CodeRequired, TriggerHot},
		{"plain http frontend fetch gets deny", func(in *Input) {
			hot(in)
			in.Accept = "*/*"
		}, protocol.VerdictDeny, CodeRequired, TriggerHot},
		{"plain http navigation redirects", func(in *Input) {
			hot(in)
			in.Accept = "*/*"
			in.UpgradeInsecure = true
		}, protocol.VerdictRedirect, CodeRequired, TriggerHot},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := nav(p)
			tc.mutate(&in)

			res := Check(in, key, noRevoke{}, clearedAll{})

			if res.Verdict != tc.verdict || res.Code != tc.code {
				t.Fatalf("got %s/%s, want %s/%s", res.Verdict, res.Code, tc.verdict, tc.code)
			}

			if res.Trigger != tc.trigger {
				t.Fatalf("trigger %q, want %q", res.Trigger, tc.trigger)
			}

			if res.Verdict != protocol.VerdictAllow && len(res.Cookies) != 1 {
				t.Fatalf("ticket cookie expected, got %v", res.Cookies)
			}

			if res.Verdict == protocol.VerdictDeny && res.Response != "captcha_required" {
				t.Fatalf("response %q", res.Response)
			}

			if res.Verdict == protocol.VerdictRedirect &&
				!strings.HasPrefix(res.RedirectURL, "/waf/captcha?rd=%2Fcart") &&
				!strings.HasPrefix(res.RedirectURL, "/waf/captcha?rd=%2Flogin") {
				t.Fatalf("redirect %q", res.RedirectURL)
			}
		})
	}
}

/*
 * Событие правил -- про клиента, а не про вердикт: без действующего клиренса
 * и пропуск, и виджет дают uncleared, действующий клиренс -- cleared; где о
 * клиенте ничего не узнали, события нет вовсе.
 */
func TestEvent(t *testing.T) {
	p, key := fixture(t)
	base := nav(p)
	fresh := clearance(t, p, key, base, time.Now())
	stale := clearance(t, p, key, base, time.Now().Add(-p.Clearance.TTL.D()-time.Hour))

	cases := []struct {
		name   string
		mutate func(*Input)
		event  string
	}{
		{"no cookie, cold buckets: let through", func(*Input) {}, config.OnUncleared},
		{"no cookie, hot bucket: widget", hot, config.OnUncleared},
		{"no cookie, xhr: deny with a ticket", func(in *Input) {
			hot(in)
			in.Accept = "application/json"
		}, config.OnUncleared},
		{"valid clearance", func(in *Input) { in.Clearance = fresh }, config.OnCleared},
		{"expired clearance", func(in *Input) { in.Clearance = stale }, config.OnUncleared},
		{"full sess bucket: the clearance no longer counts", func(in *Input) {
			in.Clearance = fresh
			in.Levels = map[string]float64{buckets.KindSess: 75}
		}, config.OnUncleared},
		{"the widget itself: nothing learned", func(in *Input) { in.URI = "/waf/captcha/c.js" }, ""},
		{"the exchange kept the headers: nothing learned", func(in *Input) {
			in.StoreUnavailable = "not_found"
		}, ""},
		{"unknown profile: nothing learned", func(in *Input) { in.Profile = nil }, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := nav(p)
			tc.mutate(&in)

			res := Check(in, key, noRevoke{}, clearedAll{})
			if res.Event != tc.event {
				t.Fatalf("event %q, want %q (%s/%s)", res.Event, tc.event, res.Verdict, res.Code)
			}
		})
	}

	t.Run("profile off: nothing learned", func(t *testing.T) {
		off, err := config.ParseProfile("off",
			[]byte(strings.Replace(profileYAML, "mode: enforce", "mode: off", 1)))
		if err != nil {
			t.Fatal(err)
		}

		if res := Check(nav(off), key, noRevoke{}, clearedAll{}); res.Event != "" {
			t.Fatalf("event %q on a profile that is off (%s)", res.Event, res.Code)
		}
	})
}

/*
 * Решение лестницы -- уточнение правил: виджет в любом виде (редирект, отказ с
 * билетом, перепроверка) -- challenge, пропуск -- allow, где решения не было --
 * пусто. Наблюдение глушит только ответ: решение остаётся тем же.
 */
func TestNext(t *testing.T) {
	p, key := fixture(t)
	fresh := clearance(t, p, key, nav(p), time.Now())

	cases := []struct {
		name   string
		mutate func(*Input)
		next   string
	}{
		{"cold buckets: let through", func(*Input) {}, config.NextAllow},
		{"hot bucket: redirect", hot, config.NextChallenge},
		{"hot bucket, xhr: deny with a ticket", func(in *Input) {
			hot(in)
			in.Accept = "application/json"
		}, config.NextChallenge},
		{"skip beats a hot bucket: let through", func(in *Input) {
			hot(in)
			in.Asked = ask(p, "ip", act(protocol.DoSkip, protocol.ApplyRequest))
		}, config.NextAllow},
		{"valid clearance: let through", func(in *Input) { in.Clearance = fresh }, config.NextAllow},
		{"full sess bucket: reverify", func(in *Input) {
			in.Clearance = fresh
			in.Levels = map[string]float64{buckets.KindSess: 75}
		}, config.NextChallenge},
		{"the widget itself: no decision", func(in *Input) { in.URI = "/waf/captcha/c.js" }, ""},
		{"unknown profile: no decision", func(in *Input) { in.Profile = nil }, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := nav(p)
			tc.mutate(&in)

			res := Check(in, key, noRevoke{}, clearedAll{})
			if res.Next != tc.next {
				t.Fatalf("next %q, want %q (%s/%s)", res.Next, tc.next, res.Verdict, res.Code)
			}
		})
	}

	t.Run("observe: the decision stands, only the reply is muted", func(t *testing.T) {
		op, okey := fixture(t)
		op.Mode = config.ModeObserve

		in := nav(op)
		hot(&in)

		res := Check(in, okey, noRevoke{}, clearedAll{})
		if res.Verdict != protocol.VerdictAllow || res.Next != config.NextChallenge ||
			res.Trigger != TriggerHot {
			t.Fatalf("got %s/%s next %q trigger %q", res.Verdict, res.Code, res.Next, res.Trigger)
		}
	})
}

func TestClearance(t *testing.T) {
	p, key := fixture(t)
	in := nav(p)
	hot(&in)
	in.Clearance = clearance(t, p, key, in, time.Now())

	res := Check(in, key, noRevoke{}, clearedAll{})
	if res.Verdict != protocol.VerdictAllow || res.Code != CodeOK {
		t.Fatalf("got %s/%s", res.Verdict, res.Code)
	}

	if res.Headers["X-WAF-Captcha"] != "image" {
		t.Fatalf("header %v", res.Headers)
	}

	t.Run("other subnet", func(t *testing.T) {
		bad := in
		bad.ClientIP = "198.51.100.7"

		res := Check(bad, key, noRevoke{}, clearedAll{})
		if res.Verdict != protocol.VerdictRedirect || res.Code != CodeClearanceBind {
			t.Fatalf("got %s/%s", res.Verdict, res.Code)
		}
	})

	/*
	 * Механизм "кука и список": подпись доказывает выдачу, запись в списке --
	 * что клиренс не погасили. Запись есть -- живёт, записи нет -- погашен,
	 * списка не видно -- виджет, свежий -- едет на одной подписи.
	 */
	t.Run("list truth", func(t *testing.T) {
		lp, err := config.ParseProfile("default", []byte(profileYAML+`
clearance:
  list: captcha_cleared
`))
		if err != nil {
			t.Fatal(err)
		}

		if err := lp.Validate(); err != nil {
			t.Fatal(err)
		}

		aged := nav(lp)
		hot(&aged)
		aged.Clearance = clearance(t, lp, key, aged, time.Now().Add(-time.Minute))

		cases := []struct {
			name   string
			mirror Clearances
			code   string
		}{
			{"в списке", cleared{ready: true, ids: map[string]bool{"jti-1": true}}, CodeOK},
			{"записи нет -- погашен", cleared{ready: true}, CodeClearanceRevoked},
			{"списка не видно -- виджет", cleared{ready: false}, CodeListUnavailable},
			{"зеркала нет вовсе -- виджет", nil, CodeListUnavailable},
		}

		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				res := Check(aged, key, noRevoke{}, c.mirror)

				if res.Code != c.code {
					t.Fatalf("got %s/%s, want %s", res.Verdict, res.Code, c.code)
				}
			})
		}

		// Свежий клиренс без записи едет на одной подписи: запись ещё в пути.
		fresh := nav(lp)
		hot(&fresh)
		fresh.Clearance = clearance(t, lp, key, fresh, time.Now())

		if res := Check(fresh, key, noRevoke{}, cleared{ready: true}); res.Code != CodeOK {
			t.Fatalf("fresh got %s/%s", res.Verdict, res.Code)
		}
	})

	/*
	 * Личная корзина судит клиренс: переполнилась -- виджет заново, новая
	 * кука. Это и есть замена reverify_at.
	 */
	t.Run("full sess bucket reverifies", func(t *testing.T) {
		full := in
		full.Levels = map[string]float64{buckets.KindSess: 75}

		res := Check(full, key, noRevoke{}, clearedAll{})
		if res.Verdict != protocol.VerdictRedirect || res.Code != CodeReverify ||
			res.Trigger != TriggerReverify {
			t.Fatalf("got %s/%s/%s", res.Verdict, res.Code, res.Trigger)
		}
	})

	t.Run("warm sess bucket passes", func(t *testing.T) {
		warm := in
		warm.Levels = map[string]float64{buckets.KindSess: 40}

		res := Check(warm, key, noRevoke{}, clearedAll{})
		if res.Verdict != protocol.VerdictAllow {
			t.Fatalf("got %s/%s", res.Verdict, res.Code)
		}
	})

	/*
	 * Общие корзины сессионщика не судят: подсеть может гореть целиком, а он
	 * ходит спокойно -- в этом и смысл куки.
	 */
	t.Run("shared buckets do not judge the session holder", func(t *testing.T) {
		hot := in
		hot.Levels = map[string]float64{
			buckets.KindIP:     100,
			buckets.KindNet:    100,
			buckets.KindRouter: 100,
		}

		res := Check(hot, key, noRevoke{}, clearedAll{})
		if res.Verdict != protocol.VerdictAllow {
			t.Fatalf("got %s/%s", res.Verdict, res.Code)
		}
	})

	t.Run("no header without clearance", func(t *testing.T) {
		none := nav(p)

		res := Check(none, key, noRevoke{}, clearedAll{})
		if res.Headers["X-WAF-Captcha"] != "none" {
			t.Fatalf("header %v", res.Headers)
		}
	})
}

/*
 * Любая общая корзина на пороге уводит на виджет: заполнение накоплено
 * прошлыми запросами и уже пережило потери.
 */
func TestHotBucketTriggers(t *testing.T) {
	p, key := fixture(t)

	for _, kind := range []string{buckets.KindIP, buckets.KindNet, buckets.KindRouter} {
		t.Run(kind, func(t *testing.T) {
			in := nav(p)
			in.Levels = map[string]float64{kind: 60}

			res := Check(in, key, noRevoke{}, clearedAll{})

			if res.Verdict != protocol.VerdictRedirect || res.Trigger != TriggerHot {
				t.Fatalf("got %s/%s", res.Verdict, res.Trigger)
			}
		})
	}

	t.Run("below the threshold stays cold", func(t *testing.T) {
		in := nav(p)
		in.Levels = map[string]float64{buckets.KindIP: 59}

		if res := Check(in, key, noRevoke{}, clearedAll{}); res.Verdict != protocol.VerdictAllow {
			t.Fatalf("got %s", res.Verdict)
		}
	})
}

/*
 * Жёсткой петли попыток больше нет: цену провала назначают правила профиля
 * (on: fail -- заряд корзины), а лестница узнаёт о переборе по заполнению.
 * Номер попытки продолжает тикать в билете -- он живёт в аудите.
 */
func TestAttemptsNeverDenyByThemselves(t *testing.T) {
	p, key := fixture(t)
	in := nav(p)
	hot(&in)

	var ticket string

	for attempt := 1; attempt <= 10; attempt++ {
		in.Ticket = ticket

		res := Check(in, key, noRevoke{}, clearedAll{})
		if res.Verdict != protocol.VerdictRedirect {
			t.Fatalf("attempt %d: %s/%s", attempt, res.Verdict, res.Code)
		}

		if got := res.Engine["attempt"]; got != attempt {
			t.Fatalf("attempt %v, want %d", got, attempt)
		}

		ticket = res.Cookies[0].Value
	}
}

func TestObserve(t *testing.T) {
	p, key := fixture(t)
	p.Mode = config.ModeObserve

	in := nav(p)
	hot(&in)

	res := Check(in, key, noRevoke{}, clearedAll{})
	if res.Verdict != protocol.VerdictAllow || res.Code != CodeObserve {
		t.Fatalf("got %s/%s", res.Verdict, res.Code)
	}

	if res.Engine["would_verdict"] != protocol.VerdictRedirect || res.Engine["trigger"] != TriggerHot ||
		res.Engine["passive"] != true || res.Engine["would_code"] != CodeRequired {
		t.Fatalf("engine %v", res.Engine)
	}
}

// Профиля с таким именем нет: проверять нечем, и исход выбирает маршрут.
func TestUnknownProfile(t *testing.T) {
	_, key := fixture(t)

	res := Check(Input{Ask: "nope"}, key, noRevoke{}, clearedAll{})
	if res.Verdict != protocol.VerdictError || res.Code != CodeUnknownProfile {
		t.Fatalf("got %s/%s", res.Verdict, res.Code)
	}
}

func TestReturnPath(t *testing.T) {
	for raw, want := range map[string]string{
		"/cart":                   "/cart",
		"//evil.example":          "",
		"http://x/":               "",
		"/a b":                    "",
		"/ok?x=1":                 "/ok?x=1",
		strings.Repeat("/a", 600): "",
	} {
		if got := returnPath(raw, ""); got != want {
			t.Errorf("%q: got %q, want %q", raw, got, want)
		}
	}
}

/* --- просьбы и корзины ------------------------------------------------------ */

// Заряды принятых note: ось выбирает корзину, asn раскрывается в обе.
func TestPriorAskNotes(t *testing.T) {
	p, _ := fixture(t)

	t.Run("ip lands in the ip bucket", func(t *testing.T) {
		a := ask(p, "modsec", protocol.Action{
			Do: protocol.DoNote, Apply: protocol.ApplyIP, Value: 60})

		if len(a.Notes) != 1 || a.Notes[0].Axis != buckets.KindIP ||
			a.Notes[0].Percent != 60 {
			t.Fatalf("notes %+v", a.Notes)
		}
	})

	t.Run("asn lands in both asn buckets", func(t *testing.T) {
		a := ask(p, "modsec", protocol.Action{
			Do: protocol.DoNote, Apply: protocol.ApplyASN, Value: 5})

		if len(a.Notes) != 2 || a.Notes[0].Axis != buckets.KindNet ||
			a.Notes[1].Axis != buckets.KindRouter {
			t.Fatalf("notes %+v", a.Notes)
		}
	})

	t.Run("session lands in the sess bucket", func(t *testing.T) {
		a := ask(p, "modsec", protocol.Action{
			Do: protocol.DoNote, Apply: protocol.ApplySession, Value: -100})

		if len(a.Notes) != 1 || a.Notes[0].Axis != buckets.KindSess ||
			a.Notes[0].Percent != -100 {
			t.Fatalf("notes %+v", a.Notes)
		}
	})

	t.Run("request has no bucket", func(t *testing.T) {
		a := ask(p, "modsec", protocol.Action{
			Do: protocol.DoNote, Apply: protocol.ApplyRequest, Value: 60})

		if len(a.Notes) != 0 {
			t.Fatalf("notes %+v", a.Notes)
		}

		if a.Outcomes[0].Outcome != OutcomeNoCounter {
			t.Fatalf("outcome %q", a.Outcomes[0].Outcome)
		}
	})

	t.Run("disabled bucket is no counter", func(t *testing.T) {
		off := *p
		off.Buckets.IP = config.BucketTier{}

		a := ask(&off, "modsec", protocol.Action{
			Do: protocol.DoNote, Apply: protocol.ApplyIP, Value: 60})

		if len(a.Notes) != 0 || a.Outcomes[0].Outcome != OutcomeNoCounter {
			t.Fatalf("notes %+v outcome %q", a.Notes, a.Outcomes[0].Outcome)
		}
	})
}

// accept "*" принимает все четыре глагола -- и только от названного отправителя.
func TestPriorAskAnyVerb(t *testing.T) {
	p, _ := fixture(t)

	a := ask(p, "action",
		act(protocol.DoSkip, protocol.ApplyRequest),
		protocol.Action{Do: protocol.DoNote, Apply: protocol.ApplyIP, Value: 5},
	)

	if !a.Skip || len(a.Notes) != 1 {
		t.Fatalf("skip=%v notes=%+v", a.Skip, a.Notes)
	}

	// Чужому имени звёздочка правила action не помогает.
	b := ask(p, "stranger", act(protocol.DoSkip, protocol.ApplyRequest))

	if b.Skip || b.Outcomes[0].Outcome != OutcomeNoRule {
		t.Fatalf("skip=%v outcome=%q", b.Skip, b.Outcomes[0].Outcome)
	}
}

/*
 * Исход каждой доставленной просьбы. "Нет правила" проверяется наравне с
 * остальными: молчание в ответ на просьбу и есть тот случай, который потом
 * разбирают, и если его не записать, разбирать будет нечего.
 */
func TestActionOutcomes(t *testing.T) {
	p, key := fixture(t)

	cases := []struct {
		name    string
		from    string
		action  protocol.Action
		outcome string
		took    float64
	}{
		{"challenge applied", "ip",
			protocol.Action{Do: protocol.DoChallenge, Apply: protocol.ApplyRequest},
			OutcomeApplied, 0},

		{"skip from a sender without such a rule", "modsec",
			protocol.Action{Do: protocol.DoSkip, Apply: protocol.ApplyRequest},
			OutcomeNoRule, 0},

		{"threshold has nothing to scale", "ip",
			protocol.Action{Do: protocol.DoThreshold, Apply: protocol.ApplyRequest, Delta: 20},
			OutcomeNoCounter, 0},

		{"note taken in percent of capacity", "modsec",
			protocol.Action{Do: protocol.DoNote, Apply: protocol.ApplyIP, Value: 60},
			OutcomeApplied, 60},

		{"discount comes with the sign", "modsec",
			protocol.Action{Do: protocol.DoNote, Apply: protocol.ApplyIP, Value: -40},
			OutcomeApplied, -40},

		{"request axis has no bucket", "modsec",
			protocol.Action{Do: protocol.DoNote, Apply: protocol.ApplyRequest, Value: 60},
			OutcomeNoCounter, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := nav(p)
			in.Asked = ask(p, tc.from, tc.action)

			res := Check(in, key, noRevoke{}, clearedAll{})

			raw, ok := res.Engine["actions"]
			if !ok {
				t.Fatal("engine.actions is missing: a request that was made must be visible")
			}

			got, ok := raw.([]ActionOutcome)
			if !ok || len(got) != 1 {
				t.Fatalf("engine.actions = %#v, want one outcome", raw)
			}

			if got[0].Outcome != tc.outcome {
				t.Fatalf("outcome %q, want %q", got[0].Outcome, tc.outcome)
			}

			if got[0].Took != tc.took {
				t.Fatalf("took %v, want %v", got[0].Took, tc.took)
			}

			if got[0].From != tc.from || got[0].Do != tc.action.Do {
				t.Fatalf("from/do = %q/%q", got[0].From, got[0].Do)
			}
		})
	}
}

/*
 * Свой виджет: страница, скрипт, проверка и картинки под path профиля. Капча
 * на них -- рекурсия, и инспектор на этой локации отвечает allow до любой
 * лестницы, даже когда страница профиля требует проверку всегда.
 */
func TestOwnPathAllows(t *testing.T) {
	p, key := fixture(t)

	for _, uri := range []string{"/waf/captcha", "/waf/captcha/verify", "/waf/captcha/c.js"} {
		in := Input{Profile: p, Ask: "default", Method: "POST", URI: uri,
			ClientIP: "203.0.113.42", Now: time.Now()}

		res := Check(in, key, noRevoke{}, clearedAll{})

		if res.Verdict != protocol.VerdictAllow || res.Code != CodeSelf {
			t.Fatalf("%s: verdict %s code %s, want allow/%s", uri, res.Verdict, res.Code, CodeSelf)
		}
	}

	in := Input{Profile: p, Ask: "default", Method: "GET", URI: "/waf/captchas",
		ClientIP: "203.0.113.42", Accept: "text/html", Now: time.Now()}

	if res := Check(in, key, noRevoke{}, clearedAll{}); res.Code == CodeSelf {
		t.Fatalf("/waf/captchas is not the widget path, got %s", res.Code)
	}
}

/*
 * gate.inline: тот же билет, что у редиректа, но вердикт deny с записью
 * отказа -- страницу положит вызывающий. Запасной адрес редиректа остаётся
 * заполненным: без страницы вызывающий отвечает им.
 */
func TestInlineDeniesWithTicket(t *testing.T) {
	p, err := config.ParseProfile("default",
		[]byte(strings.Replace(profileYAML, "gate: {}", "gate: {inline: true}", 1)))
	if err != nil {
		t.Fatal(err)
	}

	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}

	_, key := fixture(t)

	in := Input{Profile: p, Ask: "default", Method: "GET", URI: "/login",
		ClientIP: "203.0.113.42", Accept: "text/html", UserAgent: "ua", Now: time.Now()}

	res := Check(in, key, noRevoke{}, clearedAll{})

	if res.Verdict != protocol.VerdictDeny || !res.Inline {
		t.Fatalf("verdict %s inline=%v, want deny inline", res.Verdict, res.Inline)
	}

	if res.Response != p.Gate.DenyResponse {
		t.Fatalf("response %q, want %q", res.Response, p.Gate.DenyResponse)
	}

	if len(res.Cookies) != 1 || res.Cookies[0].Name != p.Challenge.Cookie {
		t.Fatalf("ticket cookie missing: %+v", res.Cookies)
	}

	if !strings.HasPrefix(res.RedirectURL, "/waf/captcha?rd=") {
		t.Fatalf("fallback redirect %q", res.RedirectURL)
	}

	// Не навигация -- обычный отказ, без страницы и без билета в inline.
	in.Method = "POST"

	if res := Check(in, key, noRevoke{}, clearedAll{}); res.Inline {
		t.Fatalf("POST must not get the inline page")
	}
}

// Прежний рычаг читается как inline одно поколение.
func TestLegacyFormResponseMeansInline(t *testing.T) {
	p, err := config.ParseProfile("default",
		[]byte(strings.Replace(profileYAML, "gate: {}", "gate: {form_response: captcha_form}", 1)))
	if err != nil {
		t.Fatal(err)
	}

	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}

	if !p.FormInline() {
		t.Fatal("form_response must map to inline")
	}
}
