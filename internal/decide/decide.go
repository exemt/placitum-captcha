/*
 * Лестница вердикта капчи. Чистая функция: ни шины, ни обменника, ни Redis --
 * всё, что нужно для решения, приходит аргументом, и её можно проверить
 * таблицей.
 *
 *   mode off                                            → allow
 *   mode observe                                        → allow (would_* в аудит,
 *                                                         корзины и просьбы живые)
 *   клиренс открылся, цел, привязан, jti в списке,
 *       и личная корзина ниже порога                    → allow + X-WAF-Captcha
 *   правило: when never; корзины и счёт ниже порогов,
 *       when score и порог не взят, prior не сработал   → allow
 *   попытки билета исчерпаны                            → deny too_many
 *   не навигация                                        → deny captcha_required (+ билет)
 *   иначе                                               → redirect path?rd=… + билет
 *
 * Корзины (docs/buckets.md) считает вызывающий: он ходит в
 * Redis, здесь только уровни в процентах. Просьбы соседей он же разбирает
 * заранее (PriorAsk) -- их заряды должны попасть в тот же поход.
 *
 * Билет кладётся и на deny: модуль применяет cookies на отказ, а SPA с ним
 * приходит на /waf/captcha/api. Попытка считается на каждом билете: и на
 * redirect, и на deny -- иначе fetch в цикле получал бы билеты бесконечно.
 */

package decide

import (
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/exemt/placitum-captcha/internal/audit"
	"github.com/exemt/placitum-captcha/internal/buckets"
	"github.com/exemt/placitum-captcha/internal/config"
	"github.com/exemt/placitum-captcha/internal/protocol"
	"github.com/exemt/placitum-captcha/internal/token"
)

// Коды причины: едут модулю, попадают в диагностический заголовок и аудит.
const (
	CodeOK               = "CAPTCHA_OK"
	CodeOff              = "CAPTCHA_OFF"
	CodeSelf             = "CAPTCHA_SELF"
	CodeObserve          = "CAPTCHA_OBSERVE"
	CodeNotRequired      = "CAPTCHA_NOT_REQUIRED"
	CodeRequired         = "CAPTCHA_REQUIRED"
	CodeReverify         = "CAPTCHA_REVERIFY"
	CodeExhausted        = "CAPTCHA_EXHAUSTED"
	CodeClearanceBad     = "CAPTCHA_CLEARANCE_BAD"
	CodeClearanceExpired = "CAPTCHA_CLEARANCE_EXPIRED"
	CodeClearanceBind    = "CAPTCHA_CLEARANCE_BIND"
	CodeClearanceRevoked = "CAPTCHA_CLEARANCE_REVOKED"
	// Список клиренсов объявлен, но зеркало без снапшота: решать нельзя ни в
	// какую сторону, и клиренс не признаётся -- виджет, а не пропуск.
	CodeListUnavailable = "CAPTCHA_LIST_UNAVAILABLE"
	// Объект обменника лежал, а мы его не взяли: cookie не прочли, и о клиенте
	// это не говорит ничего.
	CodeStoreUnavailable = "CAPTCHA_STORE_UNAVAILABLE"
	// Обменник корзин не ответил: уровней, по которым судит лестница, нет.
	CodeBucketsUnavailable = "CAPTCHA_BUCKETS_UNAVAILABLE"
	// CodeGeoUnavailable -- правило требует кодер (write: net | asn), а тот
	// молчит, не успел в бюджет или не знает адреса. Записи не будет, и
	// молча пропускать её нельзя: решает waf_exception маршрута.
	CodeGeoUnavailable = "CAPTCHA_GEO_UNAVAILABLE"
	CodeUnknownProfile = "CAPTCHA_UNKNOWN_PROFILE"
	CodeWrongPhase     = "CAPTCHA_PHASE_NOT_SUPPORTED"
)

// Коды находок -- в аудит, для разбора инцидента.
const (
	FindingClearanceBad     = "captcha-clearance-bad"
	FindingClearanceRevoked = "captcha-clearance-revoked"
	FindingExhausted        = "captcha-exhausted"
	FindingUnknownProfile   = "captcha-unknown-profile"
	FindingStore            = "captcha-store-unavailable"
	FindingListDown         = "captcha-list-unavailable"
)

// Чем вызвано требование -- в аудит и в билет.
const (
	TriggerAlways   = "always"
	TriggerScore    = "score"
	TriggerPrior    = "prior"
	TriggerReverify = "reverify"
	TriggerHot      = "hot"
)

// Revoked -- множество отзыва из памяти. После переезда клиренсов на списки
// здесь остались только хеши отпечатков ферм (fp:<hash>).
type Revoked interface {
	Revoked(id string) bool
}

/*
 * Clearances -- зеркало активного списка клиренсов. Список -- истина: запись
 * в нём означает, что клиренс не погасили. ready=false -- списка не видно, и
 * это отказ списка, а не его пустота: клиренс не признаётся.
 */
type Clearances interface {
	Contains(subject, jti string) (ok, ready bool)
}

type Input struct {
	Profile *config.Profile
	Ask     string

	Method   string
	URI      string
	Args     string
	ClientIP string

	Clearance string
	Ticket    string
	UserAgent string
	Accept    string

	// SecFetchDest -- заголовок Sec-Fetch-Dest: document у перехода, image,
	// script, empty (fetch страницы) у подзапросов; пусто -- прислал не браузер.
	SecFetchDest string

	/*
	 * Asked -- заранее разобранные просьбы соседей (PriorAsk): их заряды
	 * уезжают в корзины тем же походом, которым читаются уровни, поэтому
	 * разбор идёт до решения.
	 */
	Asked Asked

	/*
	 * Levels -- заполнение корзин субъекта в процентах ёмкости, уже с зарядами
	 * этого запроса. Считает не эта функция: счёт живёт в Redis, здесь чистая
	 * лестница. Пустая карта -- корзины выключены.
	 */
	Levels map[string]float64

	StoreUnavailable string

	/*
	 * Opened -- уже проверенный клиренс. Проверка местная целиком: печать
	 * токена, реестр отпечатков, зеркало списка -- ни одного похода наружу,
	 * поэтому вызывающий вправе сделать её раньше и решить по её исходу, какие
	 * корзины вообще спрашивать у Redis. Пусто -- Check проверит сам, и это
	 * по-прежнему нормальный вызов.
	 */
	Opened *Opened

	Now time.Time
}

// Opened -- исход проверки клиренса. Clearance непустой означает действующий
// клиренс; Code различает причины отказа для аудита.
type Opened struct {
	Clearance *token.Clearance
	Code      string
	Findings  []audit.Finding
}

type Result struct {
	Verdict string
	Code    string

	Response       string
	RedirectURL    string
	RedirectStatus int

	/*
	 * Inline -- виджет телом ответа: вердикт deny с билетом в Cookies, а
	 * страницу вызывающий берёт у captcha-http и кладёт в обменник (лестница
	 * решает, но не ходит по сети). RedirectURL при этом заполнен запасным
	 * ходом: страница не досталась -- вызывающий отвечает редиректом.
	 */
	Inline bool

	Cookies []protocol.Cookie
	Headers map[string]string

	Clearance *token.Clearance
	Trigger   string
	Findings  []audit.Finding
	Engine    map[string]any

	/*
	 * Event -- что лестница узнала о клиенте для правил профиля: cleared --
	 * предъявил действующий клиренс, uncleared -- действующего клиренса нет
	 * (config.On*). Пусто, когда узнавать было нечего. По нему обработчик
	 * выбирает правила клиента: просьбы соседям, записи в набор, заряды.
	 */
	Event string

	/*
	 * Next -- что лестница решила с клиентом на этом запросе: challenge --
	 * потребовала проверку, allow -- пропустила (config.Next*). Пусто, когда
	 * решения не было. Уточнение правил uncleared и порогов корзин.
	 */
	Next string
}

func Check(in Input, key *token.Key, revoked Revoked, clearances Clearances) (out Result) {
	/*
	 * Событие правил и решение лестницы -- по итогу и одним местом, а не у
	 * каждого return: событие про клиента, решение -- про этот запрос.
	 */
	defer func() {
		out.Event = eventOf(in, out)
		out.Next = nextOf(out)
	}()

	// Профиля с таким именем нет: проверять этим маршрутом нечем, и выбирать за
	// него между виджетом и пропуском капча не вправе.
	if in.Profile == nil {
		return Result{
			Verdict: protocol.VerdictError,
			Code:    CodeUnknownProfile,
			Findings: []audit.Finding{{
				Code:     FindingUnknownProfile,
				Severity: audit.SeverityCritical,
				Target:   audit.TargetConn,
				Rule:     in.Ask,
			}},
		}
	}

	p := in.Profile
	engine := map[string]any{"profile": p.Name, "mode": p.Mode}

	// Наблюдение: ответ модулю заглушён на каждом запросе профиля, и флаг
	// стоит на каждой записи; would_* -- только там, где было что глушить.
	if p.Mode == config.ModeObserve {
		engine["passive"] = true
	}

	if in.StoreUnavailable != "" {
		engine["store"] = in.StoreUnavailable
	}

	if p.Mode == config.ModeOff {
		return allow(p, nil, CodeOff, engine)
	}

	/*
	 * Свой виджет: страница, скрипт, проверка и картинки под path. Капча
	 * на них -- рекурсия, поэтому allow до любой лестницы; так инспектор
	 * может стоять на локации виджета, и локейшен без инспекторов ей больше
	 * не нужен.
	 */
	if p.OwnPath(in.URI) {
		engine["self"] = true

		return allow(p, nil, CodeSelf, engine)
	}

	// Просьбы разобраны вызывающим до похода в корзины; здесь только аудит.
	asked := in.Asked

	if len(asked.Outcomes) != 0 {
		engine["actions"] = asked.Outcomes
	}

	if len(in.Levels) != 0 {
		engine["buckets"] = in.Levels
	}

	/*
	 * Коэффициент просьб threshold: проценты к накопленному счёту фазы при
	 * сравнении с нашими порогами. Сами пороги -- score_at, reverify_at -- не
	 * двигаются: число, которое написал оператор, остаётся правдой, меняется
	 * цена поведения клиента. Тройка чисел едет в аудит, иначе вердикты не
	 * объяснить.
	 */
	op := in.Opened
	if op == nil {
		o := Open(in, key, revoked, clearances)
		op = &o
	}

	clr, code, finding := op.Clearance, op.Code, op.Findings

	/*
	 * Список клиренсов -- истина, а зеркала нет: погашен этот клиренс или нет,
	 * сказать нечем. Прежний виджет заново означал, что отставшее зеркало
	 * гонит через капчу всех, кто её уже прошёл, -- и решала это капча. Теперь
	 * исход выбирает waf_exception класса inspector.
	 */
	if code == CodeListUnavailable {
		return Result{
			Verdict:  protocol.VerdictError,
			Code:     code,
			Findings: finding,
			Engine:   engine,
		}
	}

	if clr != nil {
		/*
		 * Клиента с клиренсом судит только личная корзина: подсеть может
		 * гореть целиком, а он ходит спокойно -- в этом и смысл куки.
		 * Переполнилась -- клиренс недействителен, виджет заново, новая кука
		 * с чистой корзиной.
		 */
		if !bucketFull(in, p, buckets.KindSess) {
			asked.cleared()

			return allow(p, clr, CodeOK, engine)
		}

		code = CodeReverify
		engine["sess_full"] = true
	}

	rule := p.RuleFor(in.Method, in.URI)
	if rule.Page != "" {
		engine["page"] = rule.Page
	}

	trigger := required(in, p, rule, clr != nil, asked)
	if trigger == "" {
		res := allow(p, nil, CodeNotRequired, engine)
		res.Findings = finding

		return res
	}

	engine["trigger"] = trigger
	engine["reason"] = code

	/*
	 * Наблюдение глушит только ответ модулю: билета и редиректа нет, allow с
	 * CodeObserve. Корзины, просьбы соседей и правила по заполнению
	 * (fireBucketFull у вызывающего) работают как в enforce.
	 */
	if p.Mode == config.ModeObserve {
		engine["would_verdict"] = wouldBe(in, p)
		engine["would_code"] = code

		res := allow(p, nil, CodeObserve, engine)
		res.Findings = finding
		// Решение принято, заглушён только ответ: правила с next: challenge и
		// счётчик would.* видят его так же, как в enforce.
		res.Trigger = trigger

		return res
	}

	/*
	 * Номер попытки остаётся в билете и аудите, но отказа по нему больше нет:
	 * цену провала назначают правила профиля (on: fail -- заряд корзины), и
	 * лестница узнаёт о переборе по заполнению, как обо всём остальном.
	 */
	attempt := attemptOf(in, p, key)
	engine["attempt"] = attempt

	ticket := issueTicket(in, p, key, rule, attempt)

	if navigational(in, p) {
		res := redirect(in, p, ticket, code)

		/*
		 * Виджет телом ответа на том же URI: тот же билет и тот же запасной
		 * редирект, но вердикт deny -- страницу вызывающий положит в обменник и
		 * назовёт секцией rewrite. Абсолютного адреса в контуре при этом нет.
		 */
		if p.FormInline() && ticket != nil {
			res.Verdict = protocol.VerdictDeny
			res.Response = p.Gate.DenyResponse
			res.Inline = true
			engine["inline"] = true
		}

		res.Trigger = trigger
		res.Findings = finding
		res.Engine = engine

		return res
	}

	return Result{
		Verdict:  protocol.VerdictDeny,
		Code:     code,
		Response: p.Gate.DenyResponse,
		Cookies:  ticket,
		Trigger:  trigger,
		Findings: finding,
		Engine:   engine,
	}
}

/*
 * eventOf -- событие правил профиля по итогу лестницы. cleared -- клиент
 * предъявил действующий клиренс; uncleared -- действующего клиренса у него
 * нет, что бы лестница ни решила дальше: пропустить (корзины холодные, when:
 * never, сосед попросил skip) или показать виджет (в наблюдении -- показала
 * бы). Пусто, когда о клиенте ничего не узнали: профиль выключен или не
 * найден, запрос к самому виджету, сбой списка клиренсов, кука не прочитана,
 * потому что обменник не отдал заголовки.
 */
func eventOf(in Input, res Result) string {
	switch res.Code {
	case CodeOK:
		if res.Clearance != nil {
			return config.OnCleared
		}

		return ""

	case CodeOff, CodeSelf, CodeUnknownProfile, CodeListUnavailable, "":
		return ""
	}

	// Куки не видно не потому, что её нет: обменник не отдал заголовки.
	if in.Clearance == "" && in.StoreUnavailable != "" {
		return ""
	}

	return config.OnUncleared
}

/*
 * nextOf -- что лестница решила с клиентом на этом запросе: challenge --
 * потребовала проверку (виджет редиректом или телом, отказ с билетом; в
 * наблюдении -- потребовала бы), allow -- пропустила. Пусто, когда решения не
 * было: сбой, выключенный профиль, свой путь виджета.
 */
func nextOf(res Result) string {
	switch {
	case res.Trigger != "":
		return config.NextChallenge

	case res.Verdict == protocol.VerdictAllow && res.Code != CodeOff && res.Code != CodeSelf:
		return config.NextAllow
	}

	return ""
}

/*
 * Open проверяет клиренс. Любой отказ означает одно: клиренса нет, код
 * различает причины для аудита. Возвращаемый код при отсутствии cookie --
 * CodeRequired: это и есть "требуется", а не ошибка.
 *
 * Экспортирована ради порядка походов, а не ради второй точки решения: ходить
 * в Redis за общими корзинами клиента с действующим клиренсом незачем, а
 * узнать это можно только здесь -- и здесь это ничего не стоит.
 */
func Open(in Input, key *token.Key, revoked Revoked, clearances Clearances) Opened {
	p := in.Profile
	if p == nil {
		return Opened{}
	}

	clr, code, finding := open(in, p, key, revoked, clearances)

	return Opened{Clearance: clr, Code: code, Findings: finding}
}

func open(in Input, p *config.Profile, key *token.Key, revoked Revoked,
	clearances Clearances) (*token.Clearance, string, []audit.Finding) {

	if in.Clearance == "" {
		if in.StoreUnavailable != "" {
			return nil, CodeRequired, []audit.Finding{{
				Code:     FindingStore,
				Severity: audit.SeverityHigh,
				Target:   audit.TargetConn,
				Rule:     in.StoreUnavailable,
			}}
		}

		return nil, CodeRequired, nil
	}

	want := token.Bind{}

	if p.BindsNet() {
		v4, v6 := p.NetBits()
		want.Net = token.Subnet(in.ClientIP, v4, v6)
	}

	if p.BindsUA() {
		want.UA = token.Fingerprint(in.UserAgent)
	}

	clr, err := key.OpenClearance(in.Clearance, in.Now, want)

	switch {
	case errors.Is(err, token.ErrExpired):
		return nil, CodeClearanceExpired, nil

	case errors.Is(err, token.ErrBind):
		return nil, CodeClearanceBind, bad(FindingClearanceBad, "bind")

	case err != nil:
		return nil, CodeClearanceBad, bad(FindingClearanceBad, "seal")
	}

	// Ферма: отпечаток, помеченный fp:<hash>, гасит все свои клиренсы разом.
	// Это счётчик злоупотребления, а не управление сессией -- он остался в
	// реестре.
	if revoked != nil && clr.FP != "" && revoked.Revoked("fp:"+clr.FP) {
		return nil, CodeClearanceRevoked, bad(FindingClearanceRevoked, "fp:"+clr.FP)
	}

	/*
	 * Список -- истина. Свежий клиренс проходит по одной подписи: запись едет
	 * через секвенсор контроллера и возвращается снапшотом. Дальше -- только
	 * по списку: нет записи, значит клиренс погасили.
	 */
	if p.Clearance.ListEnabled() &&
		in.Now.Sub(time.Unix(clr.Issued, 0)) > p.Clearance.Grace.D() {

		if clearances == nil {
			return nil, CodeListUnavailable, bad(FindingListDown, p.Clearance.List)
		}

		listed, ready := clearances.Contains(p.Clearance.List, clr.JTI)

		if !ready {
			return nil, CodeListUnavailable, bad(FindingListDown, p.Clearance.List)
		}

		if !listed {
			return nil, CodeClearanceRevoked, bad(FindingClearanceRevoked, clr.JTI)
		}
	}

	return clr, CodeOK, nil
}

// bucketFull -- корзина этого вида дошла до своего порога капчи. Уровни
// приходят в процентах ёмкости, уже с зарядами этого запроса; порог у каждой
// корзины свой, нулевой -- корзина считает, но на виджет не гонит.
func bucketFull(in Input, p *config.Profile, kind string) bool {
	at := p.Buckets.Tier(kind).CaptchaAt

	if at <= 0 {
		return false
	}

	level, ok := in.Levels[kind]

	return ok && level >= float64(at)
}

// hotBuckets -- общие корзины субъекта, дошедшие до порога.
func hotBuckets(in Input, p *config.Profile) []string {
	var out []string

	for _, kind := range []string{buckets.KindIP, buckets.KindNet, buckets.KindRouter} {
		if bucketFull(in, p, kind) {
			out = append(out, kind)
		}
	}

	return out
}

/*
 * required -- чем вызвано требование, либо пусто. Клиент с действующим
 * клиренсом сюда не доходит; hadClearance значит, что мы здесь по reverify.
 */
func required(in Input, p *config.Profile, rule config.Rule, hadClearance bool,
	ask Asked) string {

	if hadClearance {
		return TriggerReverify
	}

	// Просьба пропустить гасит всё остальное, включая when: always. Она
	// действует только там, где оператор включил её правилом с именем
	// отправителя, поэтому это его решение, а не соседа.
	if ask.Skip {
		return ""
	}

	switch rule.When {
	case config.WhenNever:
		return ""

	case config.WhenAlways:
		return TriggerAlways
	}

	/*
	 * Горячая корзина выше счёта запроса и выше просьб: заполнение накоплено
	 * прошлыми запросами и уже пережило потери. Ждать, пока наберут баллы ещё
	 * и здесь, значило бы спрашивать дважды об одном.
	 */
	if len(hotBuckets(in, p)) > 0 {
		return TriggerHot
	}

	if ask.Want {
		return TriggerPrior
	}

	return ""
}

/*
 * Asked -- что соседи попросили и что из этого прошло через правила профиля.
 * Нулевая структура означает "никто ничего не просил либо ни одно правило не
 * подошло", и это самый частый исход.
 */
type Asked struct {
	Want bool // показать проверку
	Skip bool // не проверять этот запрос вовсе
	// Notes -- принятые изменения корзин: проценты ёмкости, знак значим.
	// В единицы счёта их переводит вызывающий -- у него ёмкости под рукой
	// там же, где Redis.
	Notes []Note

	// Outcomes -- по строке на каждую доставленную просьбу, для kind=inspector.
	Outcomes []ActionOutcome
}

// Note -- одно принятое изменение: ось с провода и проценты ёмкости.
type Note struct {
	Axis    string
	Percent int
	Code    string
}

// Исход одной просьбы. "Нет правила" -- полноправный исход, а не пропуск:
// молчание в ответ на просьбу и есть тот случай, который потом разбирают.
const (
	OutcomeApplied = "applied"
	OutcomeNoRule  = "no_rule"
	// OutcomeNoCounter -- правило подошло, но корзины для этой оси нет:
	// выключена в профиле либо оси не положено (request).
	OutcomeNoCounter = "no_counter"
	// OutcomeCleared -- просьба показать проверку принята, но клиент уже
	// предъявил действующий клиренс: человек проверен, виджета не будет.
	// Прежде такая просьба числилась «применённой», и по аудиту выходило,
	// что капча показана, -- а её не было.
	OutcomeCleared = "cleared"
)

/*
 * ActionOutcome -- что сосед просил и что из этого вышло у нас. Без исхода
 * запись бесполезна: видно, что просьба была, и не видно, почему ничего не
 * случилось.
 *
 * Три исхода "не доставлено" сюда попасть не могут по построению -- пассивный
 * отправитель, переполнение waf_actions_max и урезание по маршруту отсекаются
 * до нас, и живут они в записи модуля kind=request.
 */
type ActionOutcome struct {
	From  string `json:"from"`
	Do    string `json:"do"`
	Apply string `json:"apply"`
	Code  string `json:"code,omitempty"`
	Value int    `json:"value,omitempty"`
	Delta int    `json:"delta,omitempty"`

	// Took -- что мы взяли: проценты коэффициента либо проценты ёмкости.
	Took    float64 `json:"took,omitempty"`
	Outcome string  `json:"outcome"`
}

/*
 * PriorAsk -- просьбы соседей против правил профиля. Зовёт вызывающий до
 * решения: заряды принятых note должны уехать в корзины тем же походом,
 * которым читаются уровни.
 */
func PriorAsk(prior []protocol.PriorVerdict, p *config.Profile) Asked {
	var a Asked

	if p == nil {
		return a
	}

	/*
	 * Только записи фазы запроса. Капча живёт на ней одной (на прочих фазах
	 * отвечает "не моя фаза"), поэтому сквозная prior приезжает к ней ровно
	 * раз, и накопительный note снимается один раз без всякой отметки. Тому,
	 * кто стоит на нескольких фазах, этого мало: он обязан сверять фазу записи
	 * со своей текущей -- docs/inspector-actions.md, «Накопительные действия и
	 * фазы», и так делает счётчик.
	 */
	for _, v := range prior {
		if v.Phase != "" && v.Phase != protocol.PhaseRequest {
			continue
		}

		for _, act := range v.Actions {
			a.deliver(v.Inspector, act, p)
		}
	}

	return a
}

/*
 * deliver -- одна просьба против всех правил профиля. Цикл по действиям снаружи,
 * а не по правилам: исход у просьбы один, сколько бы правил её ни зацепило, и
 * собрать его можно только здесь.
 */
func (a *Asked) deliver(from string, act protocol.Action, p *config.Profile) {
	out := ActionOutcome{
		From:    from,
		Do:      act.Do,
		Apply:   act.Scope(),
		Code:    act.Code,
		Value:   act.Value,
		Delta:   act.Delta,
		Outcome: OutcomeNoRule,
	}

	for _, r := range p.Trigger.Prior {
		if r.From != config.AnyInspector && r.From != from {
			continue
		}

		if !r.Accepts(act.Do) || !r.WantsCode(act.Code) {
			continue
		}

		a.take(act, p, &out)
	}

	a.Outcomes = append(a.Outcomes, out)
}

// take -- применить одно действие по подошедшему правилу. Потолков больше
// нет: границы держат загрузчик отправителя и ёмкость корзины.
func (a *Asked) take(act protocol.Action, p *config.Profile, out *ActionOutcome) {
	switch act.Do {
	case protocol.DoChallenge:
		a.Want = true
		out.apply(0)

	case protocol.DoSkip:
		a.Skip = true
		out.apply(0)

	case protocol.DoThreshold:
		// Счёт фазы триггером быть перестал -- масштабировать нечего.
		// Правило подошло, но применить просьбу некуда.
		out.noCounter()

	case protocol.DoNote:
		a.note(act, p, out)
	}
}

/*
 * cleared -- клиент с действующим клиренсом: просьбы показать проверку приняты
 * по правилу, но исполнять их нечем. Исход меняется на месте -- срез исходов
 * уже лежит в engine["actions"], и аудит увидит правду: cleared, а не applied.
 * Кто хочет перепроверить человека, шлёт note session: личная корзина
 * переполняется, клиренс гаснет, и следующий challenge исполнится.
 */
func (a *Asked) cleared() {
	for i := range a.Outcomes {
		out := &a.Outcomes[i]

		if out.Do == protocol.DoChallenge && out.Outcome == OutcomeApplied {
			out.Outcome = OutcomeCleared
		}
	}
}

// apply -- исход "принято"; повторное правило только суммирует взятое.
func (o *ActionOutcome) apply(took float64) {
	o.Outcome = OutcomeApplied
	o.Took += took
}

// noCounter -- правило подошло, но корзины для оси нет. Не "нет правила":
// правило есть, и разбирать надо профиль корзины, а не правило.
func (o *ActionOutcome) noCounter() {
	if o.Outcome == OutcomeNoRule {
		o.Outcome = OutcomeNoCounter
	}
}

/*
 * note -- «изменить корзину»: value с провода -- проценты её ёмкости, плюс
 * пополняет, минус снимает (−100% при уровне не выше ёмкости гарантированно
 * обнуляет: выше ёмкости уровень не бывает).
 *
 * Ось выбирает корзину: ip -- адрес, session -- личная корзина клиренса, asn
 * -- обе ASN-корзины: сигнал один, шкалы две -- подсеть греется быстро, вся
 * система медленно. request корзины не имеет.
 */
func (a *Asked) note(act protocol.Action, p *config.Profile, out *ActionOutcome) {
	if act.Value == 0 {
		// Менять корзину на ноль -- не изменение: правило сработало, но
		// вливать нечего.
		out.apply(0)
		return
	}

	var kinds []string

	switch act.Scope() {
	case protocol.ApplyIP:
		if p.Buckets.IP.Enabled() {
			kinds = append(kinds, buckets.KindIP)
		}

	case protocol.ApplySession:
		if p.Buckets.Sess.Enabled() {
			kinds = append(kinds, buckets.KindSess)
		}

	case protocol.ApplyASN:
		if p.Buckets.ASNNet.Enabled() {
			kinds = append(kinds, buckets.KindNet)
		}

		if p.Buckets.ASNRouter.Enabled() {
			kinds = append(kinds, buckets.KindRouter)
		}
	}

	if len(kinds) == 0 {
		out.noCounter()
		return
	}

	out.apply(float64(act.Value))

	for _, kind := range kinds {
		a.Notes = append(a.Notes, Note{
			Axis:    kind,
			Percent: act.Value,
			Code:    act.Code,
		})
	}
}

/*
 * attemptOf -- номер попытки, которую сейчас выдаём. Билет несёт прошлую;
 * нет билета или он чужой/истёк -- первая. Билет истекает сам, так что
 * клиент, ушедший на полчаса, начинает счёт заново -- это намеренно: цикл
 * рвётся в пределах challenge.ttl, а не навсегда.
 */
func attemptOf(in Input, p *config.Profile, key *token.Key) int {
	if in.Ticket == "" {
		return 1
	}

	t, err := key.OpenTicket(in.Ticket, in.Now)
	if err != nil || t.Profile != p.Name {
		return 1
	}

	return t.Attempt + 1
}

func issueTicket(in Input, p *config.Profile, key *token.Key, rule config.Rule,
	attempt int) []protocol.Cookie {

	ticket := &token.Ticket{
		Nonce:   token.NewID(),
		Return:  returnPath(in.URI, in.Args),
		Profile: p.Name,
		Attempt: attempt,
		Expiry:  in.Now.Add(p.Challenge.TTL.D()).Unix(),
	}

	if p.BindsNet() {
		v4, v6 := p.NetBits()
		ticket.Net = token.Subnet(in.ClientIP, v4, v6)
	}

	if p.BindsUA() {
		ticket.UA = token.Fingerprint(in.UserAgent)
	}

	sealed, err := key.SealTicket(ticket)
	if err != nil {
		return nil
	}

	return []protocol.Cookie{{
		Name:   p.Challenge.Cookie,
		Value:  sealed,
		Path:   p.Path,
		MaxAge: int(p.Challenge.TTL.D().Seconds()),
	}}
}

func bad(code, rule string) []audit.Finding {
	return []audit.Finding{{
		Code:     code,
		Severity: audit.SeverityMedium,
		Target:   audit.TargetConn,
		Rule:     rule,
	}}
}

/*
 * allow ставит заголовок приложению -- всегда, включая "none": снять
 * подделанный клиентом заголовок модуль не может, только перезаписать.
 */
func allow(p *config.Profile, c *token.Clearance, code string, engine map[string]any) Result {
	res := Result{
		Verdict:   protocol.VerdictAllow,
		Code:      code,
		Headers:   map[string]string{},
		Clearance: c,
		Engine:    engine,
	}

	value := "none"

	if c != nil {
		value = c.Provider
		engine["jti"] = c.JTI
		engine["provider"] = c.Provider
	}

	if p.Upstream.Header != "" {
		res.Headers[p.Upstream.Header] = value
	}

	return res
}

func redirect(in Input, p *config.Profile, ticket []protocol.Cookie, code string) Result {
	if ticket == nil {
		// Запечатать нечем -- страницы без билета не будет. Отказ честнее.
		return Result{
			Verdict:  protocol.VerdictDeny,
			Code:     code,
			Response: p.Gate.DenyResponse,
		}
	}

	target := p.Path

	if back := returnPath(in.URI, in.Args); back != "" {
		target += "?rd=" + url.QueryEscape(back)
	}

	return Result{
		Verdict:        protocol.VerdictRedirect,
		Code:           code,
		RedirectURL:    target,
		RedirectStatus: p.Gate.RedirectStatus,
		Cookies:        ticket,
	}
}

func navigational(in Input, p *config.Profile) bool {
	if !p.RedirectsMethod(in.Method) {
		return false
	}

	if p.Gate.HTMLOnly && !showsPage(in) {
		return false
	}

	return true
}

// showsPage -- покажет ли браузер ответ страницей. Браузер говорит это сам:
// Sec-Fetch-Dest document или фрейм -- переход, остальное -- подзапрос картинки,
// скрипта или fetch страницы. Accept тут не помощник: favicon.ico просит
// «image/..., всё подряд», и по «всё подряд» получал бы редирект с новым
// билетом -- страница виджета, открытая раньше, устаревала бы. Без заголовка
// решает Accept: так ходят curl и fetch из node. Режим (Sec-Fetch-Mode) не
// смотрится: fetch из node шлёт cors на любой запрос.
func showsPage(in Input) bool {
	switch in.SecFetchDest {
	case "":
		return acceptsHTML(in.Accept)
	case "document", "iframe", "frame":
		return true
	default:
		return false
	}
}

func acceptsHTML(accept string) bool {
	if accept == "" {
		return false
	}

	return strings.Contains(accept, "text/html") ||
		strings.Contains(accept, "application/xhtml+xml") ||
		strings.Contains(accept, "*/*")
}

func wouldBe(in Input, p *config.Profile) string {
	if navigational(in, p) {
		return protocol.VerdictRedirect
	}

	return protocol.VerdictDeny
}

// returnPath -- только локальный путь; всё, что не похоже на него,
// отбрасывается целиком: пустой rd лучше открытого редиректа.
func returnPath(uri, args string) string {
	const max = 1024

	if uri == "" || uri[0] != '/' || strings.HasPrefix(uri, "//") {
		return ""
	}

	out := uri
	if args != "" {
		out += "?" + args
	}

	if len(out) > max {
		return ""
	}

	for i := 0; i < len(out); i++ {
		c := out[i]
		if c < 0x21 || c > 0x7e || c == '\\' {
			return ""
		}
	}

	return out
}
