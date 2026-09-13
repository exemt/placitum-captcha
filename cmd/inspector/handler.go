/*
 * Конвейер одного сообщения: разбор -> очередь -> бюджет -> обменник -> решение.
 *
 * Ответ уходит на каждом пути, включая панику: молчание неотличимо от
 * перегрузки. Единственный поход наружу -- чтение заголовков из обменника:
 * cookie клиренса инлайном не едет.
 */

package main

import (
	"context"
	"errors"
	"log/slog"
	"runtime/debug"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-captcha/internal/audit"
	"github.com/exemt/placitum-captcha/internal/buckets"
	"github.com/exemt/placitum-captcha/internal/config"
	"github.com/exemt/placitum-captcha/internal/decide"
	"github.com/exemt/placitum-captcha/internal/livelist"
	"github.com/exemt/placitum-captcha/internal/protocol"
	"github.com/exemt/placitum-captcha/internal/queue"
	"github.com/exemt/placitum-captcha/internal/roster"
	"github.com/exemt/placitum-captcha/internal/stats"
	"github.com/exemt/placitum-captcha/internal/store"
)

const (
	codeUnsupportedVersion = "CAPTCHA_UNSUPPORTED_VERSION"
	codeMalformed          = "CAPTCHA_MALFORMED_REQUEST"
	codeInternalError      = "CAPTCHA_INTERNAL_ERROR"
)

type handler struct {
	cfg        *config.Config
	log        *slog.Logger
	nc         *nats.Conn
	audit      *audit.Sink
	profiles   *config.Store
	store      *store.Redis
	roster     roster.Roster
	pool       *queue.Pool
	stats      *stats.Counters
	buckets    *buckets.Store
	resolver   geoResolver
	lists      listWriter
	clearances *livelist.Mirror
	// forms -- страница виджета для deny телом ответа; nil без адреса
	// captcha-http, и тогда inline-профили отвечают редиректом.
	forms *formFetcher
}

func (h *handler) receive(msg *nats.Msg) {
	defer h.recoverInto(msg.Reply, "")

	req, err := protocol.Parse(msg.Data)
	if err != nil {
		rid := ""

		var pe *protocol.ParseError
		if errors.As(err, &pe) {
			rid = pe.RID
		}

		h.log.Warn("message rejected", "error", err.Error(), "bytes", len(msg.Data))
		h.send(msg.Reply, protocol.FallbackReply(rid, h.cfg.Name, codeMalformed), nil,
			audit.Details{})

		return
	}

	/*
	 * Незнакомая версия схемы и чужая фаза -- расхождение конфигурации: проверки
	 * не было, и распорядиться этим должен маршрут, а не капча.
	 */
	if !h.cfg.Supports(req.V) {
		reply := protocol.ErrorReply(req, codeUnsupportedVersion)
		reply.V = protocol.Version
		h.send(msg.Reply, reply, req, audit.Details{})

		return
	}

	// Капча живёт только в фазе запроса: redirect в фазе ответа запрещён.
	if req.Phase != protocol.PhaseRequest {
		h.send(msg.Reply, protocol.ErrorReply(req, decide.CodeWrongPhase), req,
			audit.Details{})

		return
	}

	h.pool.Submit(&queue.Task{Req: req, Reply: msg.Reply})
}

func (h *handler) evaluate(t *queue.Task, budget time.Duration, shed string) {
	defer h.recoverInto(t.Reply, t.Req.RID)

	if shed != "" {
		/*
		 * Сброшенный запрос -- не проверенный запрос. Раньше здесь стоял allow с
		 * доводом «под нагрузкой не уводить всех на форму»: довод верный, но это
		 * решение маршрута, а не инспектора, и теперь его говорит
		 * waf_exception … inspector pass.
		 */
		reply := protocol.ShedReply(t.Req, shed)
		det := audit.Details{
			Engine: map[string]any{
				"shed":      shed,
				"budget_ms": float64(budget.Microseconds()) / 1000,
			},
		}

		asks := h.overloadOnShed(t, shed, reply, det)

		h.log.Warn("shed", "rid", t.Req.RID, "reason", shed, "budget_ms", budget.Milliseconds(),
			"asks", asks)
		h.send(t.Reply, reply, t.Req, det)

		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	reply, det := h.inspect(ctx, t.Req, t.Fill)
	h.send(t.Reply, reply, t.Req, det)
}

func (h *handler) inspect(ctx context.Context, req *protocol.Request, fill int) (
	*protocol.Reply, audit.Details) {

	start := time.Now()

	snap := h.profiles.Current()
	profile, _ := snap.Profile(req.Route.Profile)

	in := decide.Input{
		Profile:  profile,
		Ask:      req.Route.Profile,
		Method:   req.HTTP.Method,
		URI:      req.HTTP.URI,
		ClientIP: req.Conn.ClientIP,
		Now:      time.Now(),
	}

	var levels []buckets.Level

	if profile != nil && profile.Mode != config.ModeOff {
		pairs, args, why, fault := store.Pair(ctx, h.store, req.Store.Headers, req.Store.Args)

		/*
		 * Заголовки лежали, а обменник их не отдал. "Сессии не видно" здесь
		 * означало бы "клиент пришёл без cookie", и лестница увела бы на форму
		 * каждого вошедшего: отказ обслуживания под видом обычного решения.
		 */
		if fault {
			h.log.Error("store fetch failed", "rid", req.RID,
				"profile", profile.Name, "reason", why)

			return protocol.ErrorReply(req, decide.CodeStoreUnavailable), audit.Details{
				Engine: map[string]any{"profile": profile.Name, "store": why},
			}
		}

		in.Args = args
		in.StoreUnavailable = why
		in.Clearance = store.Cookie(pairs, profile.Clearance.Cookie)
		in.Ticket = store.Cookie(pairs, profile.Challenge.Cookie)
		in.UserAgent = store.Value(pairs, "user-agent")
		in.Accept = store.Value(pairs, "accept")
		in.SecFetchMode = store.Value(pairs, "sec-fetch-mode")

		/*
		 * Просьбы соседей разбираются до похода в корзины: их заряды уезжают
		 * тем же pipeline, которым читаются уровни, -- и уровень возвращается
		 * уже с ними. Реакция мгновенная: порог, взятый этим запросом, виден
		 * этому же запросу, на каком бы экземпляре он ни приземлился.
		 */
		in.Asked = decide.PriorAsk(req.Prior, profile)

		/*
		 * Клиренс проверяется до похода в корзины. Проверка местная целиком --
		 * печать, реестр отпечатков, зеркало списка, -- и знать её исход
		 * заранее нужно затем, что клиента с действующим клиренсом судит
		 * только его личная корзина. Остальные три спрашивать не за чем, а
		 * лестница ниже переиспользует уже готовый разбор.
		 */
		opened := decide.Open(in, h.cfg.Key, h.roster, h.clearances)
		in.Opened = &opened

		if profile.Buckets.Enabled() {
			subj := h.subjectsOf(ctx, profile, req.Conn.ClientIP, in.Clearance)
			tiers := tiersOf(profile)

			var err error

			levels, err = h.buckets.Apply(ctx, profile.Name, tiers,
				chargesOf(subj, tiers, in.Asked.Notes),
				readsOf(subj, tiers, opened.Clearance != nil))
			if err != nil {
				/*
				 * Общего счёта по этому запросу нет: лестница судит по уровням
				 * корзин, и своя доля трафика ответила бы порогом экземпляра
				 * вместо порога контура. Ни увести на виджет, ни пропустить за
				 * маршрут капча не вправе -- решает waf_exception.
				 */
				h.log.Error("buckets unavailable", "rid", req.RID,
					"profile", profile.Name, "error", err.Error())

				return protocol.ErrorReply(req, decide.CodeBucketsUnavailable),
					audit.Details{Engine: map[string]any{
						"profile": profile.Name,
						"buckets": err.Error(),
					}}
			}

			in.Levels = percentsOf(levels)
		}
	}

	res := decide.Check(in, h.cfg.Key, h.roster, h.clearances)

	/*
	 * Виджет телом ответа: страница в обменник, адрес -- в реплай. Не вышло --
	 * редирект на виджет, как у обычного профиля: билет клиенту уже выписан,
	 * и лестница заполнила запасной адрес заранее.
	 */
	var rewrite *protocol.Rewrite

	if res.Inline {
		rw, err := h.inlineForm(ctx, req, profile, res, in.UserAgent)
		if err != nil {
			h.log.Warn("inline widget unavailable, redirecting instead",
				"rid", req.RID, "profile", profile.Name, "error", err.Error())
			h.stats.Inc("inline.fallback")

			res.Verdict = protocol.VerdictRedirect
			res.Response = ""
			res.Inline = false
			res.Engine["inline_fallback"] = err.Error()
		} else {
			rewrite = rw
		}
	}

	// Корзина дошла до порога, клиент пришёл с действующим клиренсом или без
	// него -- срабатывают правила профиля: записи в наборы (дальше режет
	// локальный слой модуля), заряды, просьбы соседям. Пачка идёт в порядке
	// «пороги, потом клиент»: из двух просьб об одной группе модификатор
	// исполняет последнюю.
	var fired []protocol.Action

	if profile != nil && profile.Mode != config.ModeOff {
		subj := h.subjectsOf(ctx, profile, req.Conn.ClientIP, in.Clearance)

		var err error

		fired, err = h.fireBucketFull(ctx, profile, subj, req.Conn.ClientIP, levels, res.Next)

		if err == nil && res.Event != "" {
			var more []protocol.Action

			more, err = h.fireClient(ctx, profile, subj, req.Conn.ClientIP, res.Event, res.Next,
				res.Clearance)
			fired = append(fired, more...)
		}

		// Правила перегрузки: запрос встал в очередь не ниже их порога.
		if err == nil {
			var more []protocol.Action

			more, err = h.fireOverload(ctx, profile, subj, req.Conn.ClientIP, fill, false)
			fired = append(fired, more...)
		}

		/*
		 * Правило требует кодер, а кодер молчит: запись в набор не состоялась.
		 * Молча пропустить нельзя -- бан, которого не было, выглядит как бан,
		 * -- поэтому error, и что делать с запросом, решает waf_exception.
		 */
		if err != nil {
			h.log.Error("geo unavailable for a list write", "rid", req.RID,
				"profile", profile.Name, "error", err.Error())

			return protocol.ErrorReply(req, decide.CodeGeoUnavailable),
				audit.Details{Engine: map[string]any{
					"profile": profile.Name,
					"geo":     err.Error(),
				}}
		}
	}

	elapsed := time.Since(start)

	reply := toReply(req, res)
	reply.Rewrite = rewrite
	reply.Actions = append(reply.Actions, fired...)

	h.stats.Inc("verdict." + reply.Verdict)

	if res.Trigger != "" {
		h.stats.Inc("trigger." + res.Trigger)
	}

	if profile != nil && profile.Mode == config.ModeObserve && res.Trigger != "" {
		h.stats.Inc("would." + res.Trigger)
	}

	if res.Code == decide.CodeUnknownProfile {
		h.log.Error("unknown profile",
			"rid", req.RID,
			"profile", req.Route.Profile,
			"client_ip", req.Conn.ClientIP,
		)
	}

	h.log.Info("verdict",
		"rid", req.RID,
		"inspector", req.Inspector,
		"profile", req.Route.Profile,
		"method", req.HTTP.Method,
		"uri", req.HTTP.URI,
		"client_ip", req.Conn.ClientIP,
		"verdict", reply.Verdict,
		"reason", res.Code,
		"trigger", res.Trigger,
	)

	return reply, audit.Details{
		EngineMS: float64(elapsed.Microseconds()) / 1000,
		Findings: res.Findings,
		Engine:   res.Engine,
	}
}

func toReply(req *protocol.Request, res decide.Result) *protocol.Reply {
	reply := protocol.NewReply(req, res.Verdict)

	if res.Code != "" {
		reply.Reason = &protocol.Reason{Code: res.Code}
	}

	switch res.Verdict {
	case protocol.VerdictAllow:
		for name, value := range res.Headers {
			reply.SetHeader(name, value)
		}

	case protocol.VerdictRedirect:
		reply.Redirect = &protocol.RedirectRef{
			URL:    res.RedirectURL,
			Status: res.RedirectStatus,
		}
		reply.Cookies = res.Cookies

	case protocol.VerdictDeny:
		if res.Response != "" {
			reply.Response = &protocol.ResponseRef{Name: res.Response}
		}

		// Билет едет и на отказ: модуль применяет cookies к deny, и SPA с
		// ним приходит на /waf/captcha/api.
		reply.Cookies = res.Cookies
	}

	return reply
}

func (h *handler) send(subject string, reply *protocol.Reply, req *protocol.Request,
	det audit.Details) {

	if subject == "" {
		h.log.Error("no reply subject in message", "rid", reply.RID)
		return
	}

	payload, err := reply.Marshal()
	if err != nil {
		h.log.Error("reply marshal failed", "rid", reply.RID, "error", err.Error())

		payload, err = protocol.FallbackReply(reply.RID, reply.Inspector,
			codeInternalError).Marshal()
		if err != nil {
			return
		}
	}

	if err := h.nc.Publish(subject, payload); err != nil {
		h.log.Error("respond failed", "rid", reply.RID, "error", err.Error())
	}

	if err := h.audit.Add(req, reply, det); err != nil {
		h.log.Warn("audit publish failed", "rid", reply.RID, "error", err.Error())
	}
}

func (h *handler) recoverInto(subject, rid string) {
	r := recover()
	if r == nil {
		return
	}

	h.log.Error("handler panicked", "rid", rid, "panic", r, "stack", string(debug.Stack()))

	if subject != "" {
		h.send(subject, protocol.FallbackReply(rid, h.cfg.Name, codeInternalError), nil,
			audit.Details{})
	}
}

/*
 * overloadOnShed -- правила перегрузки на снятом по полной очереди запросе:
 * срабатывают все, каков бы ни был порог, и только на фазе запроса. Просьбы
 * едут рядом с error, модуль исполнит свои глаголы; записи и заряды капча
 * делает сама. Субъект считается, только если его ждёт заряд корзины.
 */
func (h *handler) overloadOnShed(t *queue.Task, shed string, reply *protocol.Reply,
	det audit.Details) int {

	if shed != queue.ReasonQueueLimit || t.Req.Phase != protocol.PhaseRequest {
		return 0
	}

	profile, _ := h.profiles.Current().Profile(t.Req.Route.Profile)
	if profile == nil || profile.Mode == config.ModeOff {
		return 0
	}

	ctx := context.Background()

	var subj subject

	if chargesOnOverload(profile) {
		subj = h.subjectsOf(ctx, profile, t.Req.Conn.ClientIP, "")
	}

	actions, err := h.fireOverload(ctx, profile, subj, t.Req.Conn.ClientIP, t.Fill, true)
	if err != nil {
		h.log.Error("geo unavailable for a list write", "rid", t.Req.RID,
			"profile", profile.Name, "error", err.Error())

		det.Engine["geo"] = err.Error()
	}

	if len(actions) != 0 {
		reply.Actions = actions
	}

	return len(actions)
}
