/*
 * Субъекты корзин на стороне обработчика: ключи, заряды и записи в наборы.
 *
 * Лестница остаётся чистой -- она читает уровни и заранее разобранные просьбы;
 * кто такой этот субъект, куда падают заряды и что уезжает в набор, знает
 * процесс. Спека -- docs/buckets.md.
 */

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/exemt/placitum-captcha/internal/buckets"
	"github.com/exemt/placitum-captcha/internal/config"
	"github.com/exemt/placitum-captcha/internal/decide"
	"github.com/exemt/placitum-shared/netinfo"
	"github.com/exemt/placitum-captcha/internal/protocol"
	"github.com/exemt/placitum-captcha/internal/token"
)

/*
 * Кодер и набор -- за интерфейсами, чтобы путь записи проверялся без шины и
 * без gRPC. Боевые реализации -- netinfo.Resolver и dataset.Publisher; обе
 * nil-безопасны, поэтому nil-указатель в интерфейсе работает как «нет».
 */
type geoResolver interface {
	Resolve(ctx context.Context, raw string) (network, router string)
	Lookup(ctx context.Context, addr netip.Addr, expand bool) (netinfo.Info, error)
}

type listWriter interface {
	Add(name, value string, ttl time.Duration, reason string) error
	AddMany(name string, values []string, ttl time.Duration, reason string) error
}

/*
 * subject -- ключи субъекта этого запроса по корзинам. Пустой ключ означает
 * "корзины нет для этого клиента": сеть не разрешилась, куки нет. Пустые ключи
 * отбрасывает сам Store.
 */
type subject struct {
	ip     string
	sess   string
	net    string
	router string
}

func (s subject) key(kind string) string {
	switch kind {
	case buckets.KindIP:
		return s.ip
	case buckets.KindSess:
		return s.sess
	case buckets.KindNet:
		return s.net
	case buckets.KindRouter:
		return s.router
	}

	return ""
}

var bucketKinds = []string{
	buckets.KindIP, buckets.KindSess, buckets.KindNet, buckets.KindRouter,
}

// clearedKinds -- что читается у клиента с действующим клиренсом. Ровно его
// личная корзина: остальные его не судят.
var clearedKinds = []string{buckets.KindSess}

func tiersOf(p *config.Profile) map[string]buckets.Tier {
	return map[string]buckets.Tier{
		buckets.KindIP:     {Max: p.Buckets.IP.Max, Loss: p.Buckets.IP.Loss},
		buckets.KindSess:   {Max: p.Buckets.Sess.Max, Loss: p.Buckets.Sess.Loss},
		buckets.KindNet:    {Max: p.Buckets.ASNNet.Max, Loss: p.Buckets.ASNNet.Loss},
		buckets.KindRouter: {Max: p.Buckets.ASNRouter.Max, Loss: p.Buckets.ASNRouter.Loss},
	}
}

/*
 * subjectsOf -- ключи корзин. Анонс и номер системы спрашиваются у кодера
 * только когда есть корзины по системам: ключам записи они не нужны -- та
 * ходит к кодеру сама, в момент записи. Резолв синхронный, в бюджете
 * сообщения; молчащий кодер даёт пустые ключи, и корзины по системам этот
 * запрос не считают -- видно в журнале, но вердикт из-за ключа не рушится.
 */
func (h *handler) subjectsOf(ctx context.Context, p *config.Profile, clientIP, clearance string) subject {
	var s subject

	if p.Buckets.IP.Enabled() {
		s.ip = buckets.IPKey(clientIP)
	}

	/*
	 * Ключ личной корзины -- хеш запечатанной куки, не её содержимое: для
	 * ключа хватает стабильности на срок куки, а открывать её здесь незачем.
	 * Новая кука -- новый ключ -- чистая корзина, ровно как задумано.
	 */
	if p.Buckets.Sess.Enabled() && clearance != "" {
		sum := sha256.Sum256([]byte(clearance))
		s.sess = hex.EncodeToString(sum[:8])
	}

	if p.Buckets.ASNNet.Enabled() || p.Buckets.ASNRouter.Enabled() {
		network, router := h.resolver.Resolve(ctx, clientIP)

		if p.Buckets.ASNNet.Enabled() {
			s.net = network
		}

		if p.Buckets.ASNRouter.Enabled() {
			s.router = router
		}
	}

	return s
}

// chargesOf переводит принятые note из процентов ёмкости в единицы счёта.
func chargesOf(s subject, tiers map[string]buckets.Tier, notes []decide.Note) []buckets.Charge {
	var out []buckets.Charge

	for _, n := range notes {
		key := s.key(n.Axis)
		tier := tiers[n.Axis]

		if key == "" || !tier.Enabled() {
			continue
		}

		out = append(out, buckets.Charge{
			Ref: buckets.Ref{Kind: n.Axis, Key: key},
			Add: float64(n.Percent) / 100 * tier.Max,
		})
	}

	return out
}

/*
 * readsOf -- какие корзины этот запрос обязан прочитать.
 *
 * У клиента с действующим клиренсом судит только личная корзина: общие его не
 * оценивают (decide.Check возвращает allow по одной sess, а required при
 * hadClearance до общих корзин не доходит вовсе). Правила бана из-за этого
 * ничего не теряют: порог берётся на том запросе, который корзину зарядил, а
 * заряженная корзина приезжает в уровнях независимо от списка чтения --
 * см. refUnion в internal/buckets.
 *
 * На живом маршруте пропущенных клиентов большинство, поэтому это три ключа
 * из четырёх на каждом их запросе.
 */
func readsOf(s subject, tiers map[string]buckets.Tier, cleared bool) []buckets.Ref {
	kinds := bucketKinds
	if cleared {
		kinds = clearedKinds
	}

	var out []buckets.Ref

	for _, kind := range kinds {
		if key := s.key(kind); key != "" && tiers[kind].Enabled() {
			out = append(out, buckets.Ref{Kind: kind, Key: key})
		}
	}

	return out
}

// percentsOf -- уровни для лестницы: вид корзины -> заполнение в процентах.
func percentsOf(levels []buckets.Level) map[string]float64 {
	if len(levels) == 0 {
		return nil
	}

	out := make(map[string]float64, len(levels))

	for _, l := range levels {
		out[l.Kind] = l.Percent
	}

	return out
}

/*
 * fireBucketFull -- корзина дошла до порога: срабатывают правила профиля.
 * Порогов два: captcha_at (on: bucket_captcha) и ban_at (on: bucket_ban).
 * Что делать, решает оператор: запись в набор (и дальше режет локальный слой
 * модуля или инспектор адреса), заряд другой корзины, просьба соседу -- она
 * возвращается и уезжает в ответе этого же запроса, инспектор на волне.
 *
 * Правила срабатывают на каждом запросе, пока корзина выше порога, и
 * глушилки на минуту здесь нет намеренно. Просьба соседу живёт один запрос --
 * заглушённая, она доехала бы один раз и пропала, и «маска, пока корзина
 * полна» стала бы «маска на один ответ». Трафик горячего субъекта
 * останавливает не память процесса, а то, для чего запись и делается: бан по
 * адресу режет край до шины. Памяти нет и у записи: повтор продлевает срок,
 * см. writeList.
 *
 * next -- что лестница решила с клиентом на этом запросе: правило с next
 * срабатывает только на своём решении («порог взят, но капча пропустила» --
 * повод замаскировать выдачу, «порог взят и виджет показан» -- взять цену).
 *
 * Ошибка -- только от кодера: правило требует анонс или состав системы, а
 * кодер молчит. Такой запрос отвечает error, и решает waf_exception маршрута.
 */
func (h *handler) fireBucketFull(ctx context.Context, p *config.Profile, subj subject, clientIP string,
	levels []buckets.Level, next string) ([]protocol.Action, error) {

	if len(p.Rules) == 0 {
		return nil, nil
	}

	var actions []protocol.Action
	var charges []buckets.Charge
	tiers := tiersOf(p)

	for _, l := range levels {
		tier := p.Buckets.Tier(l.Kind)

		// Пороги у каждой корзины свои; нулевой порог не срабатывает.
		steps := []struct {
			on string
			at int
		}{
			{config.OnBucketCaptcha, tier.CaptchaAt},
			{config.OnBucketBan, tier.BanAt},
		}

		for _, step := range steps {
			if step.at == 0 || l.Percent < float64(step.at) {
				continue
			}

			for _, r := range p.RulesFor(step.on, l.Kind, next) {
				switch {
				case r.Do != "":
					actions = append(actions, askOf(r))

				case r.List != "":
					if err := h.writeList(ctx, r, clientIP, "", code(r, l.Kind)); err != nil {
						return nil, err
					}

				case r.Charge != "":
					if key := subj.key(r.Charge); key != "" && tiers[r.Charge].Enabled() {
						charges = append(charges, buckets.Charge{
							Ref: buckets.Ref{Kind: r.Charge, Key: key},
							Add: float64(r.Percent) / 100 * tiers[r.Charge].Max,
						})
					}
				}
			}
		}
	}

	if len(charges) > 0 {
		if _, err := h.buckets.Apply(context.Background(), p.Name, tiers,
			charges, nil); err != nil {
			// Заряды по исходу: вердикт этого запроса от них не зависит, и
			// ронять его нечем -- но потеря заряда обязана быть видна.
			h.log.Warn("buckets charge failed", "profile", p.Name, "error", err.Error())
		}
	}

	return actions, nil
}

/*
 * fireClient -- правила событий клиента: cleared (предъявил действующий
 * клиренс) и uncleared (действующего клиренса нет). Оба -- состояние, а не
 * событие, и срабатывают на каждом таком запросе: просьба канала действует на
 * один запрос, повторная запись в набор продлевает срок, заряд ложится снова
 * (отрицательный упирается в пустую корзину, положительный на состоянии
 * копится с каждым запросом). Однократное «прошёл виджет» -- событие pass,
 * его отрабатывает captcha-http.
 *
 * cleared -- единственное положительное, что капча знает о клиенте, и
 * единственное, чем она может ослабить соседей: снять корзину счётчику, дать
 * скидку modsec, не звать vlai. uncleared -- обратное: человек не проверен, и
 * соседям дальше по цепочке это стоит знать на каждом его запросе -- включить
 * классификатор, замаскировать выдачу, добавить очков. Просьба доедет, только
 * если запрос пойдёт дальше: виджет обрывает фазу, пока капча не стоит в
 * vote. Куки у uncleared нет, и write: cid ему загрузчик не даёт.
 *
 * next -- решение лестницы на этом запросе: у uncleared правило может ждать
 * своего -- пропустила (включить соседей) или показала виджет (цена показа:
 * бот, который виджет игнорирует, копит корзину до бана).
 */
func (h *handler) fireClient(ctx context.Context, p *config.Profile, subj subject, clientIP, on, next string,
	clr *token.Clearance) ([]protocol.Action, error) {

	rules := p.RulesFor(on, "", next)

	if len(rules) == 0 {
		return nil, nil
	}

	var cid string

	if clr != nil {
		cid = clr.CID
	}

	var actions []protocol.Action
	var charges []buckets.Charge
	tiers := tiersOf(p)

	for _, r := range rules {
		switch {
		case r.Do != "":
			actions = append(actions, askOf(r))

		case r.List != "":
			reason := r.Code
			if reason == "" {
				reason = "CAPTCHA_" + strings.ToUpper(on)
			}

			if err := h.writeList(ctx, r, clientIP, cid, reason); err != nil {
				return nil, err
			}

		case r.Charge != "":
			key := subj.key(r.Charge)

			if key == "" || !tiers[r.Charge].Enabled() {
				continue
			}

			charges = append(charges, buckets.Charge{
				Ref: buckets.Ref{Kind: r.Charge, Key: key},
				Add: float64(r.Percent) / 100 * tiers[r.Charge].Max,
			})
		}
	}

	if len(charges) > 0 {
		if _, err := h.buckets.Apply(context.Background(), p.Name, tiers,
			charges, nil); err != nil {
			h.log.Warn("buckets charge failed", "profile", p.Name, "error", err.Error())
		}
	}

	return actions, nil
}

/*
 * writeList -- запись субъекта в живой набор по правилу.
 *
 * Адрес и кука известны из сообщения. Анонсы и состав системы -- у кодера, и
 * спрашиваются в момент записи, синхронно, в бюджете сообщения: модулю всё
 * равно ждать инспектора, а «пусто на первом запросе» -- это молча
 * несостоявшийся бан. Кодер нужен и молчит -- запись не состоится, и это
 * ошибка, не пропуск.
 *
 * Что пишется: addr -- адрес; net -- эффективный анонс (лайт); net_all --
 * все анонсы, накрывающие адрес, от узкого к широкому (хард); asn -- состав
 * системы эффективного анонса целиком; cid -- кука. Всё одним кадром keeper с
 * одним сроком и поводом: либо вся запись, либо никак.
 *
 * Памяти «уже записано» нет, и это намеренно. Правило порога срабатывает на
 * каждом запросе, пока корзина выше порога, и каждое срабатывание -- запись.
 * Повторы режет сам бан: набор стоит перед капчей (инспектор адреса, локальная
 * проверка края), и забаненный до неё не доходит; а повторный add у keeper
 * лишь продлевает срок -- клиент продолжает долбиться, бан продлевается.
 * Память процесса здесь была глушилкой: у каждой копии своя, переживала снятие
 * бана в панели (капча не банила того же клиента заново до конца срока) и
 * росла на скане без предела.
 */
func (h *handler) writeList(ctx context.Context, r config.EventRule, clientIP, cid, reason string) error {
	if h.lists == nil {
		return nil
	}

	ttl := r.TTL.D()

	var values []string

	switch r.Write {
	case config.WriteCID:
		if cid == "" {
			return nil
		}

		values = []string{cid}

	case config.WriteNet, config.WriteNetAll, config.WriteASN:
		vals, err := h.resolveWrite(ctx, r.Write, clientIP)
		if err != nil {
			return err
		}

		values = vals

	default:
		values = []string{clientIP}
	}

	if len(values) == 0 {
		h.log.Warn("list write skipped: coder knows nothing about the address",
			"set", r.List, "write", r.Write, "addr", clientIP)

		return nil
	}

	if err := h.lists.AddMany(r.List, values, ttl, reason); err != nil {
		h.log.Warn("list write failed",
			"set", r.List, "write", r.Write, "count", len(values), "error", err.Error())

		return nil
	}

	h.log.Info("list write",
		"set", r.List, "write", r.Write, "count", len(values),
		"first", values[0], "ttl_s", int64(ttl.Seconds()), "reason", reason, "addr", clientIP)

	return nil
}

/*
 * resolveWrite -- значения записи net | net_all | asn для адреса: у кодера,
 * синхронно. Что во что разворачивается -- netinfo.Values, одна на всех
 * отправителей: лайт -- эффективный анонс, хард -- все накрывающие, система --
 * состав эффективного анонса.
 */
func (h *handler) resolveWrite(ctx context.Context, write, clientIP string) ([]string, error) {
	addr, err := netip.ParseAddr(clientIP)
	if err != nil {
		return nil, nil
	}

	info, err := h.resolver.Lookup(ctx, addr, write == config.WriteASN)
	if err != nil {
		return nil, fmt.Errorf("write %s for %s: %w", write, clientIP, err)
	}

	return netinfo.Values(info, write), nil
}

// askOf -- просьба соседу из правила, форма провода.
func askOf(r config.EventRule) protocol.Action {
	out := protocol.Action{
		To:      r.To,
		Do:      r.Do,
		Apply:   r.Axis(),
		Phase:   r.Phase,
		Code:    r.Code,
		Counter: r.Counter,
		Marker:  r.Marker,
		Group:   r.Group,
		Set:     r.Set,
		Headers: r.Headers,
		Args:    r.Args,
		Body:    r.Body,
	}

	// Срок и исход архива -- только у archive с set on; ноль в YAML значит
	// "как на маршруте", пустой исход -- "любой". Слова исхода проверены на
	// загрузке, здесь остаётся канонический порядок.
	if r.Do == protocol.DoArchive && r.Set == "on" {
		if seconds := int64(r.TTL.D().Seconds()); seconds > 0 {
			out.TTL = &seconds
		}

		if len(r.When) > 0 {
			when, _ := protocol.CheckArchiveWhen(r.When)
			out.When = when
		}
	}

	if r.Delta != nil {
		out.Delta = *r.Delta
	}

	if r.Value != nil {
		out.Value = *r.Value
	}

	return out
}

func code(r config.EventRule, kind string) string {
	if r.Code != "" {
		return r.Code
	}

	return "CAPTCHA_BUCKET_" + kind
}
