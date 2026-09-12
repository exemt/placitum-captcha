/*
 * Профиль капчи: тот самый отдельный конфиг, который задаёт оператор.
 *
 * Профиль выбирается тегом profile= записи waf_inspector и приезжает в
 * route.profile. Один процесс обслуживает сколько угодно профилей: разные
 * маршруты -- разная политика при одном сервисе.
 *
 * Всё, что здесь проверяется, проверяется при загрузке. Профиль с опечаткой
 * обязан не подняться, а не пропустить трафик мимо капчи на первом запросе.
 * Форма файла описана в docs/README.md.
 */

package config

import (
	"fmt"
	"html/template"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/exemt/placitum-captcha/internal/protocol"
)

const (
	ModeEnforce = "enforce"
	ModeObserve = "observe"
	ModeOff     = "off"

	WhenAlways = "always"
	// WhenBuckets -- виджет по заполнению корзин; прежнее имя score читается
	// одно поколение: счёт фазы триггером больше не является.
	WhenBuckets = "buckets"
	WhenNever   = "never"

	MatchExact  = "exact"
	MatchPrefix = "prefix"

	ProviderImage        = "image"
	ProviderTurnstile    = "turnstile"
	ProviderReCAPTCHA    = "recaptcha"
	ProviderHCaptcha     = "hcaptcha"
	ProviderSmartCaptcha = "smartcaptcha"

	OnErrorFallback = "fallback"
	OnErrorAllow    = "allow"
	OnErrorDeny     = "deny"

	ExhaustedDeny = "deny"
	ExhaustedPage = "page"

	RosterRedis  = "redis"
	RosterMemory = "memory"

	BindNet = "subnet"
	BindIP  = "ip"
	BindUA  = "ua"

	// AnyInspector в правиле prior -- сигнал принимается от любого соседа.
	AnyInspector = "*"
)

// DefaultName -- профиль, который применяется, когда маршрут не назвал
// никакого. ProbeName -- зарезервирован для healthcheck: when: always.
const (
	DefaultName = "default"
	ProbeName   = "_probe"
)

type Duration time.Duration

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var raw string
	if err := node.Decode(&raw); err != nil {
		return err
	}

	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "0" {
		*d = 0
		return nil
	}

	v, err := time.ParseDuration(raw)
	if err != nil {
		return err
	}

	if v < 0 {
		return fmt.Errorf("duration must not be negative: %q", raw)
	}

	*d = Duration(v)

	return nil
}

func (d Duration) D() time.Duration { return time.Duration(d) }

/*
 * Rate -- "30/m", "50/s": сколько за единицу. Отдельный тип, потому что
 * лимит, записанный двумя числами, читается хуже, чем одной строкой.
 */
type Rate struct {
	N   int
	Per time.Duration
}

func (r *Rate) UnmarshalYAML(node *yaml.Node) error {
	var raw string
	if err := node.Decode(&raw); err != nil {
		return err
	}

	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "0" {
		*r = Rate{}
		return nil
	}

	num, unit, ok := strings.Cut(raw, "/")
	if !ok {
		return fmt.Errorf("rate must look like 30/m, got %q", raw)
	}

	var n int
	if _, err := fmt.Sscanf(num, "%d", &n); err != nil || n < 0 {
		return fmt.Errorf("rate must look like 30/m, got %q", raw)
	}

	per, ok := map[string]time.Duration{"s": time.Second, "m": time.Minute, "h": time.Hour}[unit]
	if !ok {
		return fmt.Errorf("rate unit must be s, m or h, got %q", raw)
	}

	*r = Rate{N: n, Per: per}

	return nil
}

func (r Rate) Enabled() bool { return r.N > 0 }

type Profile struct {
	// Имя -- имя каталога, а не поле файла.
	Name string `yaml:"-"`

	Mode  string `yaml:"mode"`
	Path  string `yaml:"path"`
	Title string `yaml:"title"`
	Note  string `yaml:"note"`

	Trigger Trigger     `yaml:"trigger"`
	Buckets Buckets     `yaml:"buckets"`
	Rules   []EventRule `yaml:"rules"`
	Pages   []PageRule  `yaml:"pages"`
	Gate    Gate        `yaml:"gate"`
	// Provider -- основной виджет; Fallback -- запасной, на случай, когда
	// основной не загрузился, клиент без JS или siteverify лёг. Больше двух
	// не бывает: "выбери побольше" -- не политика.
	Provider    ProviderRef    `yaml:"provider"`
	Fallback    *ProviderRef   `yaml:"fallback"`
	ProviderCfg ProviderConfig `yaml:"provider_config"`
	Challenge   Challenge      `yaml:"challenge"`
	Clearance   Clearance      `yaml:"clearance"`
	Fingerprint FingerprintCfg `yaml:"fingerprint"`
	Loop        Loop           `yaml:"loop"`
	Limits      Limits         `yaml:"limits"`
	Reputation  Reputation     `yaml:"reputation"`
	List        List           `yaml:"list"`
	Upstream    Upstream       `yaml:"upstream"`
	Roster      Roster         `yaml:"roster"`
	Languages   []string       `yaml:"languages"`

	// Page -- своя страница: captcha.html рядом с profile.yaml. nil --
	// встроенная из образа.
	Page *template.Template `yaml:"-"`

	// Deprecated -- мёртвые поля, встреченные при разборе. Логируются на
	// загрузке: одно поколение они читаются и игнорируются, потом станут
	// ошибкой (docs/buckets.md).
	Deprecated []string `yaml:"-"`

	// legacyPoW -- в файле встретился провайдер pow: заменён картинкой.
	legacyPoW bool
}

/*
 * Buckets -- общий счёт субъектов (docs/buckets.md).
 * Четыре корзины на контурном Redis; наполняют их соседи просьбами note,
 * проценты считаются от ёмкости корзины. Корзина без max выключена.
 */
type Buckets struct {
	// Deprecated: пороги были общими на профиль; теперь у каждой корзины
	// свои. Читаются одно поколение и переливаются в корзины без своих.
	CaptchaAt int `yaml:"captcha_at"`
	BanAt     int `yaml:"ban_at"`

	IP        BucketTier `yaml:"ip"`
	Sess      BucketTier `yaml:"sess"`
	ASNNet    BucketTier `yaml:"asn_net"`
	ASNRouter BucketTier `yaml:"asn_router"`
}

// Tier -- корзина по виду.
func (b *Buckets) Tier(kind string) BucketTier {
	switch kind {
	case "ip":
		return b.IP
	case "sess":
		return b.Sess
	case "asn_net":
		return b.ASNNet
	case "asn_router":
		return b.ASNRouter
	}

	return BucketTier{}
}

// Enabled -- хоть одна корзина считает.
func (b Buckets) Enabled() bool {
	return b.IP.Enabled() || b.Sess.Enabled() || b.ASNNet.Enabled() ||
		b.ASNRouter.Enabled()
}

type BucketTier struct {
	// Max -- ёмкость, безразмерные единицы; 0 -- корзина выключена.
	Max float64 `yaml:"max"`
	// Loss -- потери, процентов ёмкости в секунду.
	Loss float64 `yaml:"loss"`
	// CaptchaAt -- % заполнения, при котором эта корзина гонит на виджет;
	// 0 -- считает, но на виджет не гонит.
	CaptchaAt int `yaml:"captcha_at"`
	// BanAt -- % заполнения для правил on: bucket_ban; 0 -- не срабатывает.
	BanAt int `yaml:"ban_at"`
}

func (t BucketTier) Enabled() bool { return t.Max > 0 && t.Loss > 0 }

// Повод: то же ограничение, которым модуль отбраковывает действие с провода.
var codeRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

// Имя корзины у note: алфавит имён счётчиков получателя, модульная форма та же.
var counterNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// События правил: провал попытки, прохождение виджета, два порога корзины --
// порог капчи (captcha_at) и порог бана (ban_at) -- и клиренс: есть он у
// клиента или нет. Пороговые события и клиренс живут на волне инспектора,
// поэтому им доступны и просьбы соседям; провал и прохождение случаются в
// HTTP-процессе.
//
// cleared -- запрос клиента с действующим клиренсом: человек уже проверен, и
// это единственное, что капча может сказать соседям положительного -- снять
// корзину счётчику, дать скидку modsec, не звать vlai. uncleared -- обратное:
// действующего клиренса нет (куки нет, истекла, битая, чужая сеть, погашена,
// личная корзина переполнена), что бы лестница ни решила дальше -- пропустить
// или показать виджет. Им капча включает соседей дальше по цепочке:
// классификатор, маску выдачи, очки. Оба -- состояние и срабатывают на каждом
// таком запросе: просьба канала действует на один запрос, и повторять её --
// норма, а не шум.
const (
	OnFail          = "fail"
	OnPass          = "pass"
	OnBucketCaptcha = "bucket_captcha"
	OnBucketBan     = "bucket_ban"
	OnCleared       = "cleared"
	OnUncleared     = "uncleared"
)

// onWave -- событие случается на волне инспектора: просьбы соседям доедут.
func onWave(on string) bool {
	return on == OnBucketCaptcha || on == OnBucketBan || on == OnCleared || on == OnUncleared
}

// bucketEvent -- событие порога корзины: селектор bucket имеет смысл.
func bucketEvent(on string) bool {
	return on == OnBucketCaptcha || on == OnBucketBan
}

// Решение лестницы -- уточнение next у событий, где оно бывает любым: у
// uncleared и порогов корзин. allow -- пропустила; challenge -- потребовала
// проверку: виджет редиректом или телом, отказ с билетом, в наблюдении --
// потребовала бы. У cleared решение всегда allow, у fail и pass его нет вовсе:
// они в HTTP-процессе.
const (
	NextAllow     = "allow"
	NextChallenge = "challenge"
)

// nextEvent -- решение лестницы на событии бывает любым: next имеет смысл.
func nextEvent(on string) bool {
	return on == OnUncleared || bucketEvent(on)
}

// Что писать в набор: адрес, анонсированную подсеть, номер системы либо
// куку сессии (короткий идентификатор клиренса -- его читает быстрый путь
// модуля: waf_inspect ... if $waf_request_cookies.waf_cid not in <набор>).
const (
	WriteAddr = "addr"
	// WriteNet -- лайт: только эффективный анонс, тот же, по которому
	// считаются корзины. WriteNetAll -- хард: все анонсы, накрывающие адрес,
	// включая широкие чужие. WriteASN -- состав системы эффективного анонса
	// целиком.
	WriteNet    = "net"
	WriteNetAll = "net_all"
	WriteASN    = "asn"
	WriteCID    = "cid"
)

/*
 * EventRule -- правило по событию: та же форма, что строки профиля адреса --
 * «когда → что сделать». Действие ровно одно: заряд своей корзины, запись в
 * набор либо просьба соседу. Просьбы только у событий волны -- порогов корзин
 * и клиренса: fail и pass случаются в HTTP-процессе, он не на волне, и
 * просьбе оттуда не уехать. Жёсткой механики попыток и банов больше нет --
 * всё здесь.
 */
type EventRule struct {
	On string `yaml:"on"`
	// Bucket -- у порогов корзин: какая корзина; пусто -- любая.
	Bucket string `yaml:"bucket"`
	// Next -- у uncleared и порогов: что лестница решила с клиентом на этом
	// запросе, allow или challenge; пусто -- любое решение.
	Next string `yaml:"next"`

	// Просьба соседу -- форма канала действий.
	To    string `yaml:"to"`
	Do    string `yaml:"do"`
	Apply string `yaml:"apply"`
	// Phase -- фаза вызова адресата у управляющих глаголов; пусто -- всем
	// вызовам имени.
	Phase string `yaml:"phase"`
	Delta *int   `yaml:"delta"`
	Value *int   `yaml:"value"`
	// Counter -- имя корзины получателя при do: note: селектор поверх его
	// правил приёма. Пусто -- корзину называет правило получателя.
	Counter string `yaml:"counter"`
	// Group и Set -- только при do: mutate, оба обязательны: какую группу
	// модификаторов получателя переключить и куда (on | off). У глаголов
	// записи (audit, archive) Set -- писать или нет.
	Group string `yaml:"group"`
	Set   string `yaml:"set"`
	// Marker -- только у mark, и там обязателен: метка события на записи.
	Marker string `yaml:"marker"`
	// Объекты просьбы записи (audit / archive) -- каждый со своей стороной,
	// размером и источником. Срок архива -- тот же ключ ttl, что у записи в
	// набор: у строки либо просьба, либо запись, и путать нечему.
	Headers *protocol.ObjectSpec `yaml:"headers"`
	Args    *protocol.ObjectSpec `yaml:"args"`
	Body    *protocol.ObjectSpec `yaml:"body"`
	// When -- только у archive с set on: исходы маршрута, на которых просьбу
	// исполнять (when= директивы). Пусто -- любой, включая перенаправление.
	When []string `yaml:"when"`

	// Запись в набор: имя активного набора, срок, что писать.
	List  string   `yaml:"list"`
	TTL   Duration `yaml:"ttl"`
	Write string   `yaml:"write"`

	// Заряд своей корзины: вид и ±% ёмкости.
	Charge  string `yaml:"charge"`
	Percent int    `yaml:"percent"`

	Code string `yaml:"code"`
}

var bucketKinds = []string{"ip", "sess", "asn_net", "asn_router"}

func knownBucket(kind string) bool {
	for _, k := range bucketKinds {
		if k == kind {
			return true
		}
	}

	return false
}

func validateEventRule(i int, r EventRule) error {
	at := fmt.Sprintf("rules[%d]", i)

	switch r.On {
	case OnFail, OnPass, OnBucketCaptcha, OnBucketBan, OnCleared, OnUncleared:
	default:
		return fmt.Errorf("%s: on must be fail, pass, bucket_captcha, "+
			"bucket_ban, cleared or uncleared, got %q", at, r.On)
	}

	if r.Bucket != "" {
		if !bucketEvent(r.On) {
			return fmt.Errorf("%s: bucket picks a bucket for threshold events only", at)
		}

		if !knownBucket(r.Bucket) {
			return fmt.Errorf("%s: unknown bucket %q", at, r.Bucket)
		}
	}

	switch r.Next {
	case "":

	case NextAllow, NextChallenge:
		if !nextEvent(r.On) {
			return fmt.Errorf("%s: next is for uncleared and bucket thresholds only: fail and "+
				"pass happen in the HTTP process, cleared is always let through", at)
		}

	default:
		return fmt.Errorf("%s: next must be allow or challenge, got %q", at, r.Next)
	}

	kinds := 0

	if r.Do != "" {
		kinds++
	}

	if r.List != "" {
		kinds++
	}

	if r.Charge != "" {
		kinds++
	}

	if kinds != 1 {
		return fmt.Errorf("%s: exactly one of do, list or charge", at)
	}

	if r.Do != "" {
		if !onWave(r.On) {
			return fmt.Errorf("%s: an ask needs the wave: %s happens in the "+
				"HTTP process and cannot carry actions", at, r.On)
		}

		if err := validateAsk(at, r); err != nil {
			return err
		}
	} else if r.TTL != 0 && r.List == "" {
		return fmt.Errorf("%s: ttl is only for a list write or do: archive", at)
	}

	if r.List != "" {
		switch r.Write {
		case "", WriteAddr, WriteNet, WriteNetAll, WriteASN:

		case WriteCID:
			// Кука известна там, где её выдали (on pass в HTTP) и там, где
			// её предъявили (on cleared на волне).
			if r.On != OnPass && r.On != OnCleared {
				return fmt.Errorf("%s: write cid lives on pass and cleared only: "+
					"the cookie is known where it was issued or shown", at)
			}

		default:
			return fmt.Errorf("%s: write must be addr, net, net_all, asn or cid, got %q",
				at, r.Write)
		}

		if r.TTL == 0 {
			return fmt.Errorf("%s: ttl is required for a list write", at)
		}
	}

	if r.Charge != "" {
		if !knownBucket(r.Charge) {
			return fmt.Errorf("%s: unknown bucket %q", at, r.Charge)
		}

		if r.Percent < -100 || r.Percent > 100 || r.Percent == 0 {
			return fmt.Errorf("%s: percent must be within -100..100 and not zero", at)
		}
	}

	if r.Code != "" && !codeRe.MatchString(r.Code) {
		return fmt.Errorf("%s: code %q is not [A-Z][A-Z0-9_]{0,63}", at, r.Code)
	}

	return nil
}

/*
 * validateAsk -- просьба соседу: та же отбраковка, что у модуля на проводе.
 * Словарь -- весь канал: просьбы соседям (challenge, threshold, skip, reauth,
 * note, mutate), режим вызова соседа (active, passive, vote, off) и глаголы
 * записи маршрута (audit, archive, mark, score). Капча стоит только на фазе
 * запроса, поэтому осей conn и response у неё не бывает: conn вне кадров
 * модуль отбраковывает, а записи ответа с фазы запроса не назначают.
 */
func validateAsk(at string, r EventRule) error {
	var axes []string

	switch r.Do {
	case protocol.DoChallenge, protocol.DoThreshold, protocol.DoSkip,
		protocol.DoMutate:
		axes = []string{protocol.ApplyRequest}

	case protocol.DoReauth:
		axes = []string{protocol.ApplySession}

	case protocol.DoNote:
		axes = []string{
			protocol.ApplyRequest, protocol.ApplyIP,
			protocol.ApplyASN, protocol.ApplySession,
		}

	case protocol.DoActive, protocol.DoPassive, protocol.DoVote, protocol.DoOff:
		// Режим вызова соседа до конца этой транзакции. conn -- только на
		// кадрах, а капча на кадрах не стоит.
		axes = []string{protocol.ApplyRequest}

	case protocol.DoAudit, protocol.DoArchive:
		// Запись самого маршрута: с фазы запроса назначают запись запроса.
		axes = []string{protocol.ApplyRequest}

	case protocol.DoMark, protocol.DoScore:
		// Метка на записи и очки на маршруте: исполняет модуль, адресат --
		// сам маршрут.
		axes = []string{protocol.ApplyRequest}

	default:
		return fmt.Errorf("%s: unknown do %q", at, r.Do)
	}

	apply := r.Apply

	if apply == "" && len(axes) == 1 {
		apply = axes[0]
	}

	ok := false

	for _, a := range axes {
		if a == apply {
			ok = true
		}
	}

	if !ok {
		return fmt.Errorf("%s: apply %q is not allowed for %q", at, r.Apply, r.Do)
	}

	record := recordVerb(r.Do)

	// Управляющий глагол без адресата -- бессмыслица: режим ставят одному
	// вызову, не «всем»; модуль такую просьбу отвергает.
	if controlVerb(r.Do) && r.To == "" {
		return fmt.Errorf("%s: %s needs to: the module switches one call, not everyone", at, r.Do)
	}

	if err := checkPhaseAsk(r.Do, r.Phase, r.Axis()); err != nil {
		return fmt.Errorf("%s: %w", at, err)
	}

	// Глаголы записи и очки адресованы самому маршруту: названный сосед --
	// битая форма.
	if record && r.To != "" {
		return fmt.Errorf("%s: %s takes no to: the module serves the route's own record", at, r.Do)
	}

	if r.Do == protocol.DoThreshold {
		if r.Delta == nil {
			return fmt.Errorf("%s: threshold requires delta", at)
		}

		if *r.Delta < -100 || *r.Delta > 900 {
			return fmt.Errorf("%s: delta %d is out of -100..900 percent", at, *r.Delta)
		}
	} else if r.Delta != nil {
		return fmt.Errorf("%s: delta is only for threshold", at)
	}

	switch r.Do {
	case protocol.DoNote:
		if r.Value != nil && (*r.Value < -100 || *r.Value > 100) {
			return fmt.Errorf("%s: value %d is out of -100..100 percent", at, *r.Value)
		}

		// Корзина -- селектор поверх правил приёма получателя. Пусто --
		// корзину называет его правило.
		if r.Counter != "" && !counterNameRe.MatchString(r.Counter) {
			return fmt.Errorf("%s: bad counter name %q", at, r.Counter)
		}

	case protocol.DoScore:
		// Очки: value обязателен и со знаком, адресат -- сумма маршрута.
		if r.Value == nil || *r.Value == 0 {
			return fmt.Errorf("%s: score needs a non-zero value", at)
		}

		if *r.Value < -100 || *r.Value > 100 {
			return fmt.Errorf("%s: value %d is out of -100..100", at, *r.Value)
		}

		if r.Counter != "" {
			return fmt.Errorf("%s: counter is only for note", at)
		}

	default:
		if r.Value != nil {
			return fmt.Errorf("%s: value is only for note and score", at)
		}

		if r.Counter != "" {
			return fmt.Errorf("%s: counter is only for note", at)
		}
	}

	// Группа и сторона -- только у mutate, и у mutate -- обе: «переключить»
	// без имени и стороны не просьба, а полуфраза.
	if r.Do == protocol.DoMutate {
		if r.Group == "" {
			return fmt.Errorf("%s: mutate needs a group", at)
		}

		if !counterNameRe.MatchString(r.Group) {
			return fmt.Errorf("%s: bad group name %q", at, r.Group)
		}

		if r.Set != "on" && r.Set != "off" {
			return fmt.Errorf("%s: mutate needs set: on or off, got %q", at, r.Set)
		}
	} else if r.Group != "" || (r.Set != "" && !auditVerb(r.Do)) {
		return fmt.Errorf("%s: group and set are only for mutate, audit and archive", at)
	}

	// Метка -- только у mark, и у mark она обязательна.
	if r.Do == protocol.DoMark {
		if err := protocol.CheckMarker(r.Marker); err != nil {
			return fmt.Errorf("%s: %w", at, err)
		}
	} else if r.Marker != "" {
		return fmt.Errorf("%s: marker is only for mark", at)
	}

	// Глагол записи: сторона обязательна; срок, исходы и объекты -- только у
	// archive с set on.
	if auditVerb(r.Do) {
		if r.Set != "on" && r.Set != "off" {
			return fmt.Errorf("%s: %s needs set: on or off, got %q", at, r.Do, r.Set)
		}

		if r.Set == "off" && (r.TTL != 0 || len(r.When) != 0 ||
			r.Headers != nil || r.Args != nil || r.Body != nil) {
			return fmt.Errorf("%s: ttl, when and objects are only for set on", at)
		}

		if r.Do == protocol.DoAudit && (r.TTL != 0 || len(r.When) != 0) {
			return fmt.Errorf("%s: ttl and when are only for archive", at)
		}

		if _, err := protocol.CheckArchiveWhen(r.When); err != nil {
			return fmt.Errorf("%s: %w", at, err)
		}

		for _, item := range []struct {
			name string
			spec *protocol.ObjectSpec
		}{{"headers", r.Headers}, {"args", r.Args}, {"body", r.Body}} {
			if err := protocol.CheckObjectSpec(item.name, item.spec); err != nil {
				return fmt.Errorf("%s: %w", at, err)
			}
		}
	} else {
		if len(r.When) != 0 || r.Headers != nil || r.Args != nil || r.Body != nil {
			return fmt.Errorf("%s: when, headers, args and body are only for audit and archive", at)
		}

		if r.TTL != 0 {
			return fmt.Errorf("%s: ttl is only for a list write or do: archive", at)
		}
	}

	return nil
}

// auditVerb -- глагол записи: журнал либо архив маршрута.
func auditVerb(do string) bool {
	return do == protocol.DoAudit || do == protocol.DoArchive
}

// recordVerb -- адресат глагола не сосед, а запись самого маршрута: журнал,
// архив, маркер и очки. Поля to у всех четырёх нет.
func recordVerb(do string) bool {
	return auditVerb(do) || do == protocol.DoMark || do == protocol.DoScore
}

// controlVerb -- режим вызова соседа: исполняет модуль, адресат обязателен.
func controlVerb(do string) bool {
	switch do {
	case protocol.DoActive, protocol.DoPassive, protocol.DoVote, protocol.DoOff:
		return true
	}

	return false
}

// checkPhaseAsk -- фаза вызова адресата: только у управляющих глаголов, одно
// из request, response, frame; с осью conn -- только frame либо без поля: до
// конца соединения живут одни кадры. Пусто -- всем вызовам имени.
func checkPhaseAsk(do, phase, apply string) error {
	if phase == "" {
		return nil
	}

	if !controlVerb(do) {
		return fmt.Errorf("phase is only for active, passive, vote and off")
	}

	switch phase {
	case protocol.PhaseRequest, protocol.PhaseResponse, protocol.PhaseFrame:
	default:
		return fmt.Errorf("phase must be request, response or frame, got %q", phase)
	}

	if apply == protocol.ApplyConn && phase != protocol.PhaseFrame {
		return fmt.Errorf("apply conn needs phase frame")
	}

	return nil
}

/*
 * Axis -- ось просьбы с досочинённой единственной: то, что уедет на провод.
 * Модуль ось пишет всегда, и пустая означала бы сообщение старого образца.
 */
func (r EventRule) Axis() string {
	if r.Apply != "" {
		return r.Apply
	}

	switch r.Do {
	case protocol.DoReauth:
		return protocol.ApplySession

	case protocol.DoNote:
		// Осей четыре и умолчания нет: загрузчик такое правило не пустил.
		return ""
	}

	return protocol.ApplyRequest
}

// RulesFor -- правила события; у пороговых -- совпавшие по виду корзины.
func (p *Profile) RulesFor(on, bucket, next string) []EventRule {
	var out []EventRule

	for _, r := range p.Rules {
		if r.On != on {
			continue
		}

		if r.Bucket != "" && r.Bucket != bucket {
			continue
		}

		// Решение лестницы: правило с next ждёт своего, без него -- любого.
		if r.Next != "" && r.Next != next {
			continue
		}

		out = append(out, r)
	}

	return out
}

type Trigger struct {
	When    string      `yaml:"when"`
	ScoreAt int         `yaml:"score_at"`
	Prior   []PriorRule `yaml:"prior"`
	// Deprecated: перепроверку клиренса делает личная корзина сессии
	// (buckets.sess). Поля читаются и игнорируются одно поколение.
	ReverifyAt    int      `yaml:"reverify_at"`
	ReverifyAfter Duration `yaml:"reverify_after"`
}

/*
 * Reputation -- протекающая корзина (leaky bucket) на субъекта. Скорость
 * утечки это разрешённый темп, запас до порога -- допустимый всплеск, штраф
 * соседа -- разовое вливание в ту же корзину. Отдельного "рейта" и отдельного "штрафа" нет, потому
 * что это одна величина.
 *
 * Считаем только запросы без действующего клиренса: клиент, прошедший виджет,
 * живёт в рамках своей куки и в грубые корзины не попадает. Отсюда и стимул
 * куку держать -- иначе её выгодно выбрасывать.
 */
type Reputation struct {
	IP  Tier `yaml:"ip"`
	ASN Tier `yaml:"asn"`
	// Charge -- вливания за то, что видит сама капча.
	Charge Charge `yaml:"charge"`
	/*
	 * Codes -- поле времён весов метки: цену факта называл профиль получателя.
	 * Семантика сменилась -- value с провода теперь проценты изменения счётчика
	 * (плюс -- доля порога, минус -- доля накопленного), цену держат потолок
	 * правила и порог оси, а веса не нужны. Поле читается и игнорируется, чтобы
	 * профили, записанные до перемены, не падали на загрузке.
	 */
	Codes map[string]Weights `yaml:"codes"`
	// Max -- потолок числа субъектов в памяти процесса.
	Max int `yaml:"max"`
}

// Enabled -- работает ли репутация: хотя бы одна ось включена.
func (r Reputation) Enabled() bool { return r.IP.Enabled() || r.ASN.Enabled() }

type Tier struct {
	// Leak -- разрешённый темп: сколько единиц долга стекает за период.
	Leak Rate `yaml:"leak"`
	// HotAt -- порог. Ноль -- ось считает, но никого не жжёт.
	HotAt float64 `yaml:"hot_at"`
	// Ceiling -- потолок долга: неделя атаки не должна капчить NAT сутками.
	Ceiling float64  `yaml:"ceiling"`
	HotFor  Duration `yaml:"hot_for"`
	// Subnet -- нарезка адреса в ключ. Только у оси ip; пусто -- из clearance.
	Subnet Subnet `yaml:"subnet"`
	/*
	 * PerSubject и Window -- потолок вклада одной подсети за окно. Только у
	 * оси ASN и там обязателен по смыслу: без него один скрипт в большом
	 * облаке делает горячей всю автономную систему вместе с живыми людьми.
	 */
	PerSubject float64  `yaml:"per_subject"`
	Window     Duration `yaml:"window"`
}

func (t Tier) Enabled() bool { return t.Leak.Enabled() }

// LeakPerSecond -- утечка в единицах в секунду.
func (t Tier) LeakPerSecond() float64 {
	if !t.Leak.Enabled() {
		return 0
	}

	return float64(t.Leak.N) / t.Leak.Per.Seconds()
}

// Charge -- за что вливаем сами, без соседей.
type Charge struct {
	// NoClearance -- запрос без действующего клиренса. Это и есть счёт
	// безкукового потока: единица на запрос при утечке 60/1m означает
	// "шестьдесят таких запросов в минуту с подсети -- норма".
	NoClearance float64 `yaml:"no_clearance"`
	// Exhausted -- попытки виджета исчерпаны.
	Exhausted float64 `yaml:"exhausted"`
}

// Weights -- вес одного кода по осям.
type Weights struct {
	IP  float64 `yaml:"ip"`
	ASN float64 `yaml:"asn"`
}

/*
 * PriorRule -- что мы принимаем от соседа. Это единственное место, где чужое
 * высказывание что-то значит: без правила действие соседа не применяется вовсе.
 *
 * Правило не умеет срабатывать на число соседа из prior. Не потому, что это
 * не нужно, а потому, что такое правило нельзя написать один раз и оставить:
 * score -- внутренняя шкала соседа без обещания стабильности между версиями.
 * "Мне этого достаточно" говорит отправитель действием, а не получатель по
 * чужому числу.
 */
type PriorRule struct {
	From string `yaml:"from"`
	// Accept -- глаголы; "*" -- все четыре наших. Куда падает заряд note,
	// называет сама просьба осью, фильтра осей у правила больше нет.
	Accept []string `yaml:"accept"`
	Codes  []string `yaml:"codes"`

	// Deprecated: фильтр осей и потолки умерли вместе со старой репутацией --
	// границы держат загрузчик отправителя и ёмкость корзины. Поля читаются
	// и игнорируются одно поколение (docs/buckets.md).
	Apply      []string `yaml:"apply"`
	MaxPercent int      `yaml:"max_percent"`
	MaxDelta   int      `yaml:"max_delta"`
	MaxValue   int      `yaml:"max_value"`
}

// AnyVerb в accept -- все глаголы, которые капча умеет применять.
const AnyVerb = "*"

var captchaVerbs = []string{
	protocol.DoChallenge, protocol.DoThreshold, protocol.DoSkip, protocol.DoNote,
}

// Accepts -- принимает ли правило этот глагол.
func (r PriorRule) Accepts(verb string) bool {
	for _, v := range r.Accept {
		if v == verb || v == AnyVerb {
			return true
		}
	}

	return false
}

// WantsCode -- проходит ли повод действия через фильтр правила. Пустой список
// означает "любой повод", в том числе отсутствующий.
func (r PriorRule) WantsCode(code string) bool {
	if len(r.Codes) == 0 {
		return true
	}

	for _, c := range r.Codes {
		if c == code {
			return true
		}
	}

	return false
}

/*
 * validatePrior -- ограничения загрузчика. Модель угрозы одна: один инспектор
 * скомпрометирован или сломан. Тихий адресный обход защиты хуже громкой общей
 * аварии -- первый живёт незамеченным месяцами, вторая видна в первую минуту.
 * Отсюда правило: послабление требует имени, ужесточение -- нет.
 */
func validatePrior(i int, r PriorRule) error {
	if r.From == "" {
		return fmt.Errorf("trigger.prior[%d]: from is empty (use %q for any)",
			i, AnyInspector)
	}

	if len(r.Accept) == 0 {
		return fmt.Errorf("trigger.prior[%d]: accept is required", i)
	}

	for _, verb := range r.Accept {
		switch verb {
		case AnyVerb, protocol.DoChallenge, protocol.DoThreshold,
			protocol.DoSkip, protocol.DoNote:

		case protocol.DoReauth:
			return fmt.Errorf("trigger.prior[%d]: %q is not ours to apply",
				i, verb)

		default:
			return fmt.Errorf("trigger.prior[%d]: unknown verb %q", i, verb)
		}
	}

	if r.From != AnyInspector {
		return nil
	}

	/*
	 * Широковещательное правило годится только для challenge: послабление
	 * (skip, знак threshold, знак note), доступное любому инспектору контура,
	 * -- способ для одного скомпрометированного отменить находки всех
	 * остальных.
	 */
	if containsVerb(r.Accept, AnyVerb) || r.Accepts(protocol.DoSkip) ||
		r.Accepts(protocol.DoThreshold) || r.Accepts(protocol.DoNote) {
		return fmt.Errorf("trigger.prior[%d]: only %q may come from %q: "+
			"everything else can weaken", i, protocol.DoChallenge, AnyInspector)
	}

	return nil
}

func containsVerb(list []string, verb string) bool {
	for _, v := range list {
		if v == verb {
			return true
		}
	}

	return false
}

// PageRule -- правило по пути. Нулевой ScoreAt -- взять из trigger.
type PageRule struct {
	Path    string   `yaml:"path"`
	Match   string   `yaml:"match"`
	Methods []string `yaml:"methods"`
	When    string   `yaml:"when"`
	ScoreAt int      `yaml:"score_at"`
	// Provider -- свой основной виджет для пути (запасной -- из профиля).
	Provider string `yaml:"provider"`
}

type Gate struct {
	RedirectMethods []string `yaml:"redirect_methods"`
	RedirectStatus  int      `yaml:"redirect_status"`
	DenyResponse    string   `yaml:"deny_response"`
	HTMLOnly        bool     `yaml:"html_only"`

	/*
	 * Виджет прямо на месте вместо увода на него редиректом. false -- прежнее
	 * поведение (30x на path). true -- инспектор выписывает билет, берёт
	 * страницу виджета у captcha-http внутренним запросом, кладёт её в обменник и
	 * отвечает deny с секцией rewrite; модуль отдаёт объект телом ответа на
	 * том же URI. Ни записи каталога, ни прокси-локации для этого не нужно.
	 *
	 * Зачем так: редирект уводит браузер на path абсолютным адресом, который
	 * nginx достраивает портом своего listen, и за терминатором TLS или
	 * нестандартным портом клиент уезжает не туда. Виджет на месте адреса не
	 * меняет.
	 */
	Inline bool `yaml:"inline"`

	// Deprecated: прежний рычаг того же режима -- имя записи каталога, чья
	// страница проксировала на виджет. Непустое значение читается как
	// inline: true одно поколение и больше ничего не значит.
	FormResponse string `yaml:"form_response"`

	// Deprecated: пути API умерли. Какие пути отвечают телом, а не
	// редиректом, -- свойство раскладки маршрутов сервера: на такой путь
	// вешают отдельный профиль без методов редиректа, а не список путей
	// внутри чужого профиля. Читается и игнорируется одно поколение.
	APIPaths []string `yaml:"api_paths"`
}

// ProviderRef -- строка списка providers: вид и параметры показа.
type ProviderRef struct {
	Kind   string `yaml:"kind"`
	Length int    `yaml:"length"`
	Audio  *bool  `yaml:"audio"`

	// Deprecated: ручки PoW. Провайдер умер -- он доказывал вычисление, а не
	// человечность, и садил батареи слабых устройств; темп держат корзины.
	// Поля читаются и игнорируются одно поколение.
	Difficulty         int     `yaml:"difficulty"`
	DifficultyPerScore float64 `yaml:"difficulty_per_score"`
	MaxDifficulty      int     `yaml:"max_difficulty"`
}

type ProviderConfig struct {
	PoW          PoWConfig      `yaml:"pow"`
	Image        ImageConfig    `yaml:"image"`
	Turnstile    ExternalConfig `yaml:"turnstile"`
	ReCAPTCHA    ExternalConfig `yaml:"recaptcha"`
	HCaptcha     ExternalConfig `yaml:"hcaptcha"`
	SmartCaptcha ExternalConfig `yaml:"smartcaptcha"`
}

// Deprecated: конфиг PoW читается и игнорируется одно поколение.
type PoWConfig struct {
	Algorithm string   `yaml:"algorithm"`
	TTL       Duration `yaml:"ttl"`
}

type ImageConfig struct {
	Alphabet  string   `yaml:"alphabet"`
	Languages []string `yaml:"languages"`
	// AudioDir -- каталог с <символ>.wav (16-bit PCM mono, одна частота на
	// всех). Пусто или нет каталога -- аудио-вариант не предлагается.
	AudioDir string `yaml:"audio_dir"`
}

type ExternalConfig struct {
	Version     string   `yaml:"version"`
	SiteKey     string   `yaml:"sitekey"`
	SecretEnv   string   `yaml:"secret_env"`
	SecretStore string   `yaml:"secret_store"`
	MinScore    float64  `yaml:"min_score"`
	RemoteIP    bool     `yaml:"remoteip"`
	Timeout     Duration `yaml:"timeout"`
	OnError     string   `yaml:"on_error"`
}

type Challenge struct {
	Cookie string   `yaml:"cookie"`
	TTL    Duration `yaml:"ttl"`
}

type Clearance struct {
	Cookie   string   `yaml:"cookie"`
	IDCookie string   `yaml:"id_cookie"`
	TTL      Duration `yaml:"ttl"`
	Bind     []string `yaml:"bind"`
	Subnet   Subnet   `yaml:"subnet"`

	/*
	 * List -- активный список живых клиренсов. Истина капчи: механизм один --
	 * кука и список. Выдача кладёт jti в набор, инспектор сверяет его со
	 * своим зеркалом на каждом запросе старше Grace; запись удалили --
	 * клиренса нет, что бы ни говорила подпись. Пустое имя -- списка нет,
	 * клиренс живёт одной подписью и погасить его снаружи нельзя.
	 *
	 * Grace -- окно на доезд записи через секвенсор контроллера: первые
	 * секунды после выдачи клиренс законно живёт быстрее своей записи.
	 */
	List  string   `yaml:"list"`
	Grace Duration `yaml:"grace"`

	// Deprecated: области умерли -- клиренс действует на весь сервер.
	// Двухуровневая область усложняла систему: строгому участку -- свой
	// сервер, а не свой карман внутри чужого. Читается одно поколение.
	Scope string `yaml:"scope"`
}

// ListEnabled -- ведёт ли профиль список живых клиренсов.
func (c Clearance) ListEnabled() bool { return c.List != "" }

type Subnet struct {
	V4 int `yaml:"v4"`
	V6 int `yaml:"v6"`
}

type FingerprintCfg struct {
	Collect bool     `yaml:"collect"`
	Canvas  bool     `yaml:"canvas"`
	FarmAt  int      `yaml:"farm_at"`
	Window  Duration `yaml:"window"`
}

type Loop struct {
	MaxAttempts  int      `yaml:"max_attempts"`
	OnExhausted  string   `yaml:"on_exhausted"`
	DenyResponse string   `yaml:"deny_response"`
	Lock         Duration `yaml:"lock"`
}

// Limits -- защита самого HTTP. Свойство процесса: сравнивается между
// профилями при загрузке.
type Limits struct {
	IssuePerSubnet  Rate `yaml:"issue_per_subnet"`
	VerifyPerSubnet Rate `yaml:"verify_per_subnet"`
	PendingMax      int  `yaml:"pending_max"`
	ProviderBudget  Rate `yaml:"provider_budget"`
}

// List -- активный список локального слоя. Пустой Cleared -- списка нет.
type List struct {
	Cleared string   `yaml:"cleared"`
	Banned  string   `yaml:"banned"`
	Subject string   `yaml:"subject"`
	TTL     Duration `yaml:"ttl"`
	Origin  string   `yaml:"origin"`
}

func (l List) Enabled() bool { return l.Cleared != "" }

type Upstream struct {
	Header string `yaml:"header"`
}

type Roster struct {
	Store         string   `yaml:"store"`
	Prefix        string   `yaml:"prefix"`
	RevokeRefresh Duration `yaml:"revoke_refresh"`
}

/* --- умолчания и разбор ---------------------------------------------------- */

func defaults(name string) *Profile {
	return &Profile{
		Name:  name,
		Mode:  ModeEnforce,
		Title: "Подтвердите, что вы не робот",
		Trigger: Trigger{
			When: WhenBuckets,
		},
		Gate: Gate{
			RedirectMethods: []string{"GET", "HEAD"},
			RedirectStatus:  303,
			DenyResponse:    "captcha_required",
			HTMLOnly:        true,
		},
		Provider: ProviderRef{Kind: ProviderImage},
		ProviderCfg: ProviderConfig{
			Image:        ImageConfig{Alphabet: "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"},
			Turnstile:    ExternalConfig{Timeout: Duration(3 * time.Second), OnError: OnErrorFallback},
			ReCAPTCHA:    ExternalConfig{Version: "v2", MinScore: 0.5, Timeout: Duration(3 * time.Second), OnError: OnErrorFallback},
			HCaptcha:     ExternalConfig{Timeout: Duration(3 * time.Second), OnError: OnErrorFallback},
			SmartCaptcha: ExternalConfig{Timeout: Duration(3 * time.Second), OnError: OnErrorFallback},
		},
		Challenge: Challenge{
			Cookie: "waf_cap",
			TTL:    Duration(5 * time.Minute),
		},
		Clearance: Clearance{
			Cookie:   "waf_clr",
			IDCookie: "waf_cid",
			TTL:      Duration(24 * time.Hour),
			Bind:     []string{BindNet, BindUA},
			Subnet:   Subnet{V4: 24, V6: 64},
		},
		Fingerprint: FingerprintCfg{
			Collect: true,
			FarmAt:  50,
			Window:  Duration(time.Hour),
		},
		Loop: Loop{
			MaxAttempts:  3,
			OnExhausted:  ExhaustedDeny,
			DenyResponse: "too_many",
			Lock:         Duration(15 * time.Minute),
		},
		Limits: Limits{
			IssuePerSubnet:  Rate{N: 30, Per: time.Minute},
			VerifyPerSubnet: Rate{N: 60, Per: time.Minute},
			PendingMax:      200000,
			ProviderBudget:  Rate{N: 50, Per: time.Second},
		},
		/*
		 * Репутация по умолчанию выключена: обе оси без утечки, вливаний нет.
		 * Включать её молча нельзя -- пороги зависят от трафика маршрута, и
		 * умолчание, подобранное вслепую, уводило бы на виджет живых людей.
		 *
		 * Числа ниже -- форма, а не политика: они действуют только там, где
		 * оператор задал leak, то есть назвал разрешённый темп. Вливания
		 * умолчаний не имеют вовсе, чтобы ненулевое значение всегда означало
		 * "так решил оператор", и загрузчик мог поймать заданный charge при
		 * выключенных осях.
		 */
		Reputation: Reputation{
			IP: Tier{
				HotAt:   300,
				Ceiling: 2000,
				HotFor:  Duration(10 * time.Minute),
			},
			ASN: Tier{
				HotAt:      200,
				Ceiling:    1000,
				HotFor:     Duration(30 * time.Minute),
				PerSubject: 5,
				Window:     Duration(time.Hour),
			},
			Max: 200000,
		},
		List: List{
			TTL:    Duration(24 * time.Hour),
			Origin: "captcha",
		},
		Upstream: Upstream{Header: "X-WAF-Captcha"},
		Roster: Roster{
			Store:         RosterRedis,
			Prefix:        "cap:",
			RevokeRefresh: Duration(2 * time.Second),
		},
		Languages: []string{"ru", "en"},
	}
}

// ParseProfile разбирает profile.yaml поверх умолчаний. Незнакомое поле --
// ошибка: поколение с опечаткой обязано быть отвергнуто целиком.
func ParseProfile(name string, raw []byte) (*Profile, error) {
	p := defaults(name)

	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)

	if err := dec.Decode(p); err != nil {
		return nil, fmt.Errorf("profile %s: %w", name, err)
	}

	p.Name = name

	/*
	 * PoW умер: он доказывал вычисление, а не человечность, наказывал слабые
	 * устройства и был бедным заменителем распределённого счётчика -- темп
	 * теперь держат корзины. Старые профили читаются одно поколение: pow
	 * заменяется картинкой (либо своим запасным, если он был).
	 */
	if p.Provider.Kind == "pow" {
		p.legacyPoW = true

		if p.Fallback != nil {
			p.Provider = *p.Fallback
			p.Fallback = nil
		} else {
			p.Provider = ProviderRef{Kind: ProviderImage}
		}
	}

	if p.Fallback != nil && p.Fallback.Kind == "pow" {
		p.legacyPoW = true
		p.Fallback = nil
	}

	for i := range p.Pages {
		if p.Pages[i].Provider == "pow" {
			p.legacyPoW = true
			p.Pages[i].Provider = ""
		}
	}

	p.Provider = providerDefaults(p.Provider)

	if p.Fallback != nil {
		f := providerDefaults(*p.Fallback)
		p.Fallback = &f
	}

	// Прежнее имя порогового события: bucket_full было единственным и значило
	// порог бана. Читается одно поколение, чтобы разосланное не отвергалось.
	for i := range p.Rules {
		if p.Rules[i].On == "bucket_full" {
			p.Rules[i].On = OnBucketBan
		}
	}

	// Счёт фазы триггером быть перестал: when: score читается как "по
	// корзинам", а общие пороги переливаются в корзины без своих.
	if p.Trigger.When == "score" {
		p.Trigger.When = WhenBuckets
	}

	for _, tier := range []*BucketTier{
		&p.Buckets.IP, &p.Buckets.Sess, &p.Buckets.ASNNet, &p.Buckets.ASNRouter,
	} {
		if tier.Max <= 0 {
			continue
		}

		if tier.CaptchaAt == 0 {
			tier.CaptchaAt = p.Buckets.CaptchaAt
		}

		if tier.BanAt == 0 {
			tier.BanAt = p.Buckets.BanAt
		}
	}

	for i := range p.Pages {
		if p.Pages[i].Match == "" {
			p.Pages[i].Match = MatchPrefix
		}

		if p.Pages[i].When == "" {
			p.Pages[i].When = WhenAlways
		}
	}

	return p, nil
}

func providerDefaults(ref ProviderRef) ProviderRef {
	switch ref.Kind {
	case ProviderImage:
		if ref.Length == 0 {
			ref.Length = 5
		}

		if ref.Audio == nil {
			t := true
			ref.Audio = &t
		}
	}

	return ref
}

// probeVariant -- копия профиля для healthcheck: та же страница и cookie, но
// when: always, чтобы проба без счёта и cookie получила redirect.
func (p *Profile) probeVariant() *Profile {
	c := *p
	c.Name = ProbeName
	c.Mode = ModeEnforce
	c.Trigger = Trigger{When: WhenAlways}
	c.Pages = nil

	// У пробы нет обменника, а значит и Accept: html_only отдал бы ей deny.
	c.Gate.HTMLOnly = false

	if c.Path == "" {
		c.Path = "/waf/captcha"
	}

	return &c
}

/* --- проверка -------------------------------------------------------------- */

func (p *Profile) Validate() error {
	switch p.Mode {
	case ModeEnforce, ModeObserve, ModeOff:
	default:
		return fmt.Errorf("mode must be enforce, observe or off, got %q", p.Mode)
	}

	if p.Mode == ModeEnforce && p.Path == "" {
		return fmt.Errorf("path is empty: the inspector has nowhere to send the client")
	}

	if p.Path != "" {
		if !strings.HasPrefix(p.Path, "/") {
			return fmt.Errorf("path must be an absolute path, got %q", p.Path)
		}

		if strings.ContainsAny(p.Path, "?#") {
			return fmt.Errorf("path must not carry a query or fragment, got %q", p.Path)
		}
	}

	if err := validateWhen("trigger.when", p.Trigger.When); err != nil {
		return err
	}

	if p.Trigger.ScoreAt < 0 {
		return fmt.Errorf("trigger.score_at must not be negative")
	}

	if err := p.validateBuckets(); err != nil {
		return err
	}

	for i, r := range p.Rules {
		if err := validateEventRule(i, r); err != nil {
			return err
		}
	}

	for i, r := range p.Trigger.Prior {
		if err := validatePrior(i, r); err != nil {
			return err
		}
	}

	for i, r := range p.Pages {
		if !strings.HasPrefix(r.Path, "/") {
			return fmt.Errorf("pages[%d]: path must be an absolute path, got %q", i, r.Path)
		}

		switch r.Match {
		case MatchExact, MatchPrefix:
		default:
			return fmt.Errorf("pages[%d]: match must be exact or prefix, got %q", i, r.Match)
		}

		if err := validateWhen(fmt.Sprintf("pages[%d].when", i), r.When); err != nil {
			return err
		}

		for _, m := range r.Methods {
			if m != strings.ToUpper(m) {
				return fmt.Errorf("pages[%d]: method must be upper case, got %q", i, m)
			}
		}

		if r.Provider != "" && !p.hasProvider(r.Provider) {
			return fmt.Errorf("pages[%d]: provider %q is neither provider nor fallback",
				i, r.Provider)
		}
	}

	switch p.Gate.RedirectStatus {
	case 302, 303, 307:
	default:
		return fmt.Errorf("gate.redirect_status must be 302, 303 or 307, got %d",
			p.Gate.RedirectStatus)
	}

	if p.Gate.DenyResponse == "" {
		return fmt.Errorf("gate.deny_response is empty: the module needs a catalog name")
	}

	for i, m := range p.Gate.RedirectMethods {
		if m != strings.ToUpper(m) {
			return fmt.Errorf("gate.redirect_methods[%d]: method must be upper case, got %q",
				i, m)
		}
	}

	// Прежний рычаг режима «телом ответа» -- одно поколение как синоним.
	if p.Gate.FormResponse != "" {
		p.Gate.Inline = true
	}

	if err := p.validateProviders(); err != nil {
		return err
	}

	if p.Challenge.Cookie == "" || p.Clearance.Cookie == "" || p.Clearance.IDCookie == "" {
		return fmt.Errorf("challenge.cookie, clearance.cookie and clearance.id_cookie must not be empty")
	}

	if p.Challenge.Cookie == p.Clearance.Cookie || p.Clearance.Cookie == p.Clearance.IDCookie ||
		p.Challenge.Cookie == p.Clearance.IDCookie {
		return fmt.Errorf("challenge.cookie, clearance.cookie and clearance.id_cookie must differ")
	}

	if p.Challenge.TTL == 0 || p.Clearance.TTL == 0 {
		return fmt.Errorf("challenge.ttl and clearance.ttl must be positive")
	}

	for _, b := range p.Clearance.Bind {
		if b != BindNet && b != BindIP && b != BindUA {
			return fmt.Errorf("clearance.bind: expected subnet, ip or ua, got %q", b)
		}
	}

	// Обе привязки пишут одно поле токена; вместе они значили бы «строже из
	// двух» -- лучше сказать это ошибкой, чем молча выбрать за владельца.
	if p.hasBind(BindNet) && p.hasBind(BindIP) {
		return fmt.Errorf("clearance.bind: subnet and ip are mutually exclusive")
	}

	if p.Clearance.Subnet.V4 < 0 || p.Clearance.Subnet.V4 > 32 ||
		p.Clearance.Subnet.V6 < 0 || p.Clearance.Subnet.V6 > 128 {
		return fmt.Errorf("clearance.subnet is out of range")
	}

	if p.Clearance.ListEnabled() {
		if strings.ContainsAny(p.Clearance.List, " .>*") {
			return fmt.Errorf("clearance.list must be a plain dataset name, got %q",
				p.Clearance.List)
		}

		// Окно на доезд записи через секвенсор. Ноль -- умолчание, не запрет.
		// С keeper выдача подтверждена до Set-Cookie: окна в две секунды
		// хватает с большим запасом (docs/keeper.md).
		if p.Clearance.Grace <= 0 {
			p.Clearance.Grace = Duration(2 * time.Second)
		}

		if p.Clearance.Grace > Duration(5*time.Minute) {
			return fmt.Errorf("clearance.grace must not exceed 5m, got %s",
				p.Clearance.Grace.D().String())
		}
	}

	if p.Upstream.Header == "" {
		return fmt.Errorf("upstream.header is empty")
	}

	switch p.Roster.Store {
	case RosterRedis, RosterMemory:
	default:
		return fmt.Errorf("roster.store must be redis or memory, got %q", p.Roster.Store)
	}

	if p.Roster.Prefix == "" {
		return fmt.Errorf("roster.prefix is empty")
	}

	return nil
}

func validateWhen(field, when string) error {
	switch when {
	case WhenAlways, WhenBuckets, WhenNever:
		return nil
	}

	return fmt.Errorf("%s must be always, buckets or never, got %q", field, when)
}

/*
 * validateBuckets. Корзина без ёмкости выключена -- не считает и не судит;
 * включённая обязана течь: без потерь она наполняется навсегда, и любой порог
 * рано или поздно берётся на честном трафике.
 */
func (p *Profile) validateBuckets() error {
	b := &p.Buckets

	for _, t := range []struct {
		name string
		tier BucketTier
	}{
		{"buckets.ip", b.IP}, {"buckets.sess", b.Sess},
		{"buckets.asn_net", b.ASNNet}, {"buckets.asn_router", b.ASNRouter},
	} {
		if t.tier.Max == 0 && t.tier.Loss == 0 &&
			t.tier.CaptchaAt == 0 && t.tier.BanAt == 0 {
			continue
		}

		if t.tier.Max < 0 {
			return fmt.Errorf("%s: max must not be negative", t.name)
		}

		if t.tier.Max > 0 && (t.tier.Loss <= 0 || t.tier.Loss > 100) {
			return fmt.Errorf("%s: loss must be within (0..100] percent per second",
				t.name)
		}

		if t.tier.CaptchaAt < 0 || t.tier.CaptchaAt > 100 {
			return fmt.Errorf("%s: captcha_at must be 0..100 percent", t.name)
		}

		if t.tier.BanAt != 0 && (t.tier.BanAt > 100 ||
			(t.tier.CaptchaAt > 0 && t.tier.BanAt < t.tier.CaptchaAt)) {
			return fmt.Errorf("%s: ban_at must be 0 or captcha_at..100", t.name)
		}
	}

	return nil
}

/*
 * deprecations -- мёртвые поля, встреченные в файле. Одно поколение они
 * читаются и игнорируются с предупреждением в логе -- чтобы рассылка нового
 * формата не спотыкалась о старые файлы; потом станут ошибкой.
 */
func (p *Profile) deprecations() []string {
	var out []string

	if p.Trigger.ReverifyAt != 0 || p.Trigger.ReverifyAfter != 0 {
		out = append(out, "trigger.reverify_at/reverify_after: "+
			"replaced by the sess bucket")
	}

	if p.Trigger.ScoreAt != 0 {
		out = append(out, "trigger.score_at: the phase score no longer "+
			"triggers the widget -- buckets do")
	}

	if p.Buckets.CaptchaAt != 0 || p.Buckets.BanAt != 0 {
		out = append(out, "buckets.captcha_at/ban_at: thresholds are "+
			"per-bucket now")
	}

	for i, r := range p.Trigger.Prior {
		if containsVerb(r.Accept, protocol.DoThreshold) {
			out = append(out, fmt.Sprintf("trigger.prior[%d]: threshold is "+
				"ignored: there is no phase-score trigger to scale", i))
		}
	}

	for i, r := range p.Trigger.Prior {
		if len(r.Apply) > 0 || r.MaxPercent != 0 || r.MaxDelta != 0 || r.MaxValue != 0 {
			out = append(out, fmt.Sprintf(
				"trigger.prior[%d]: apply and ceilings are ignored", i))
		}
	}

	r := &p.Reputation

	if r.IP.Enabled() || r.ASN.Enabled() || r.Charge.NoClearance != 0 ||
		r.Charge.Exhausted != 0 || len(r.Codes) > 0 {
		out = append(out, "reputation: replaced by buckets "+
			"(docs/buckets.md)")
	}

	/*
	 * Петля попыток умерла: провал и бан -- правила по событиям. Дефолты
	 * отличить от заданного нечем, поэтому предупреждение только на
	 * отклонение от них.
	 */
	if p.Loop.MaxAttempts != 3 || p.Loop.OnExhausted != ExhaustedDeny ||
		p.Loop.DenyResponse != "too_many" || p.Loop.Lock != Duration(15*time.Minute) {
		out = append(out, "loop: replaced by event rules (on: fail / bucket_full)")
	}

	// Секция list умерла: прошедших и бан пишут правила (on: pass -> write:
	// cid; on: bucket_full -> любой набор).
	if p.List.Cleared != "" || p.List.Banned != "" || p.List.Subject != "" {
		out = append(out, "list: replaced by event rules (write: cid)")
	}

	/*
	 * Пути API: отказ телом вместо редиректа -- решение раскладки маршрутов,
	 * а не список путей в профиле. На путь API вешают профиль без методов
	 * редиректа.
	 */
	if len(p.Gate.APIPaths) != 0 {
		out = append(out, "gate.api_paths: removed -- attach a redirect-less "+
			"profile to API routes instead")
	}

	// Область клиренса: теперь всегда весь сервер. host совпадает с новым
	// поведением и шума не заслуживает; profile терял бы смысл молча.
	if p.Clearance.Scope == "profile" {
		out = append(out, "clearance.scope: removed -- a clearance is valid "+
			"host-wide; give a stricter area its own server")
	}

	if p.legacyPoW {
		out = append(out, "provider pow: removed, replaced by image -- "+
			"it proved computation, not humanity, and buckets hold the pace now")
	}

	return out
}

func (p *Profile) validateProviders() error {
	if p.Provider.Kind == "" {
		return fmt.Errorf("provider is empty: a widget is required")
	}

	if p.Fallback != nil && p.Fallback.Kind == p.Provider.Kind {
		return fmt.Errorf("fallback must differ from provider")
	}

	for i, ref := range p.Refs() {

		switch ref.Kind {
		case ProviderImage:
			if ref.Length < 3 || ref.Length > 10 {
				return fmt.Errorf("providers[%d]: image length must be 3..10, got %d",
					i, ref.Length)
			}

			if len(p.ProviderCfg.Image.Alphabet) < 8 {
				return fmt.Errorf("provider_config.image.alphabet is too short")
			}

		case ProviderTurnstile, ProviderReCAPTCHA, ProviderHCaptcha, ProviderSmartCaptcha:
			cfg := p.External(ref.Kind)

			if cfg.SiteKey == "" {
				return fmt.Errorf("provider_config.%s.sitekey is empty", ref.Kind)
			}

			if cfg.SecretEnv == "" && cfg.SecretStore == "" {
				return fmt.Errorf("provider_config.%s: secret_env or secret_store is required",
					ref.Kind)
			}

			if cfg.SecretEnv != "" && cfg.SecretStore != "" {
				return fmt.Errorf("provider_config.%s: secret_env and secret_store are "+
					"mutually exclusive", ref.Kind)
			}

			switch cfg.OnError {
			case OnErrorFallback, OnErrorAllow, OnErrorDeny:
			default:
				return fmt.Errorf("provider_config.%s.on_error must be fallback, allow or deny",
					ref.Kind)
			}

			if cfg.Timeout == 0 {
				return fmt.Errorf("provider_config.%s.timeout must be positive", ref.Kind)
			}

			if ref.Kind == ProviderReCAPTCHA && cfg.Version != "v2" && cfg.Version != "v3" {
				return fmt.Errorf("provider_config.recaptcha.version must be v2 or v3")
			}

		default:
			return fmt.Errorf("providers[%d]: unknown kind %q", i, ref.Kind)
		}
	}

	return nil
}

// External -- конфигурация внешнего провайдера по виду.
func (p *Profile) External(kind string) ExternalConfig {
	switch kind {
	case ProviderTurnstile:
		return p.ProviderCfg.Turnstile
	case ProviderReCAPTCHA:
		return p.ProviderCfg.ReCAPTCHA
	case ProviderHCaptcha:
		return p.ProviderCfg.HCaptcha
	case ProviderSmartCaptcha:
		return p.ProviderCfg.SmartCaptcha
	}

	return ExternalConfig{}
}

// Refs -- основной и запасной провайдеры в порядке показа.
func (p *Profile) Refs() []ProviderRef {
	out := []ProviderRef{p.Provider}

	if p.Fallback != nil {
		out = append(out, *p.Fallback)
	}

	return out
}

func (p *Profile) hasProvider(kind string) bool {
	return p.ProviderRef(kind) != nil
}

// ProviderRef -- описание провайдера по виду; nil, если вида в профиле нет.
func (p *Profile) ProviderRef(kind string) *ProviderRef {
	if p.Provider.Kind == kind {
		return &p.Provider
	}

	if p.Fallback != nil && p.Fallback.Kind == kind {
		return p.Fallback
	}

	return nil
}

/* --- запросы к профилю ----------------------------------------------------- */

func (p *Profile) RedirectsMethod(method string) bool {
	for _, m := range p.Gate.RedirectMethods {
		if m == method {
			return true
		}
	}

	return false
}

// FormInline -- отдавать ли виджет телом ответа вместо редиректа на него.
func (p *Profile) FormInline() bool { return p.Gate.Inline }

/*
 * OwnPath -- запрос к самому виджету: страница, скрипт, проверка, картинки
 * под path профиля. Такому запросу капча не нужна по определению -- иначе
 * капча требовала бы капчу, -- и инспектор на этой локации отвечает allow.
 * Так адрес виджета не обязан быть локейшеном без инспекторов: остальные
 * (списки адресов, лимиты, modsec) там только к месту.
 */
func (p *Profile) OwnPath(uri string) bool {
	if p.Path == "" {
		return false
	}

	if uri == p.Path {
		return true
	}

	prefix := strings.TrimRight(p.Path, "/") + "/"

	return strings.HasPrefix(uri, prefix)
}

/*
 * Rule -- действующее правило для запроса: первое совпавшее из pages либо
 * сам trigger профиля. Возвращает копию с заполненными умолчаниями, чтобы
 * решающему не думать, откуда взялся порог.
 */
type Rule struct {
	When     string
	ScoreAt  int
	Page     string
	Provider string
}

func (p *Profile) RuleFor(method, uri string) Rule {
	for _, r := range p.Pages {
		if !r.matches(method, uri) {
			continue
		}

		rule := Rule{When: r.When, ScoreAt: r.ScoreAt, Page: r.Path, Provider: r.Provider}
		if rule.ScoreAt == 0 {
			rule.ScoreAt = p.Trigger.ScoreAt
		}

		return rule
	}

	return Rule{When: p.Trigger.When, ScoreAt: p.Trigger.ScoreAt}
}

func (r PageRule) matches(method, uri string) bool {
	if len(r.Methods) > 0 {
		found := false

		for _, m := range r.Methods {
			if m == method {
				found = true
				break
			}
		}

		if !found {
			return false
		}
	}

	switch r.Match {
	case MatchExact:
		return uri == r.Path
	default:
		return uri == r.Path || strings.HasPrefix(uri, r.Path)
	}
}

// BindsNet -- кука привязана к адресу: подсетью или точным адресом.
func (p *Profile) BindsNet() bool { return p.hasBind(BindNet) || p.hasBind(BindIP) }
func (p *Profile) BindsUA() bool  { return p.hasBind(BindUA) }

/*
 * NetBits -- нарезка адреса под привязку куки. При bind: ip берём полную
 * длину: смена адреса внутри той же сети уже роняет клиренс. Лимиты
 * (issue_per_subnet, verify_per_subnet) этой нарезки не видят -- они всегда
 * считают по clearance.subnet, иначе привязка к адресу заодно раздала бы
 * каждому клиенту личную корзину.
 */
func (p *Profile) NetBits() (v4, v6 int) {
	if p.hasBind(BindIP) {
		return 32, 128
	}

	return p.Clearance.Subnet.V4, p.Clearance.Subnet.V6
}

func (p *Profile) hasBind(kind string) bool {
	for _, b := range p.Clearance.Bind {
		if b == kind {
			return true
		}
	}

	return false
}

// ProviderKinds -- виды в порядке показа; для аудита и страницы.
func (p *Profile) ProviderKinds() []string {
	out := make([]string, 0, 2)

	for _, ref := range p.Refs() {
		out = append(out, ref.Kind)
	}

	return out
}
