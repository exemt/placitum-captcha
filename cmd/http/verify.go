/*
 * Выдача задания и проверка ответа -- ядро сервиса.
 *
 * Предикат выдачи клиренса:
 *
 *   билет открылся и привязка совпала
 *   и подсеть не в бане и лимиты выдачи/проверки не исчерпаны
 *   и провайдер сказал ok на ответ именно этой сессии
 *   и nonce сожжён первым
 *   → Set-Cookie waf_clr, waf_cid; событие add в cap_cleared
 *
 * Неверный ответ билет не гасит: страница показывается снова с тем же
 * nonce, а счётчик отказов считается на подсеть. Исчерпал -- бан на
 * loop.lock, и до его конца ни страницы, ни проверки.
 */

package main

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/exemt/placitum-captcha/internal/config"
	"github.com/exemt/placitum-captcha/internal/provider"
	"github.com/exemt/placitum-captcha/internal/token"
)

const (
	msgWrong    = "Ответ не принят. Попробуйте ещё раз."
	msgExpired  = "Задание устарело. Вернитесь на сайт и повторите."
	msgBanned   = "Слишком много попыток. Подождите и попробуйте позже."
	msgLimit    = "Слишком много запросов. Подождите и попробуйте позже."
	msgNoTicket = "Задания нет. Вернитесь на сайт и повторите переход."
	msgProvider = "Проверка недоступна. Попробуйте другой способ."
)

/* --- страница -------------------------------------------------------------- */

func (s *server) page(w http.ResponseWriter, r *http.Request, fallback *config.Profile,
	msg string) {

	s.pageSkipping(w, r, fallback, msg, "")
}

// pageSkipping -- страница, на которой провайдер skip уже не предлагается:
// он не ответил на проверке, и показывать его снова значит гонять клиента
// по кругу.
func (s *server) pageSkipping(w http.ResponseWriter, r *http.Request, fallback *config.Profile,
	msg, skip string) {

	p, t, err := s.session(r, fallback)
	if err != nil {
		/*
		 * Билета нет ни с редиректа, ни от инспектора (в режиме inline он
		 * приходит кукой внутреннего запроса за страницей): открыли закладкой
		 * или билет истёк. Страница «нет билета» с адресом возврата из ?rd=.
		 */
		s.render(w, p, view{NoTicket: true, Error: msgNoTicket, Lang: lang(r, p),
			ReturnTo: backTo(r, nil)}, http.StatusForbidden)

		return
	}

	ctx := r.Context()
	s.stats.Inc("page.shown")

	if !s.within(ctx, p.Limits.IssuePerSubnet, "issue", s.subnet(r, p)) {
		s.render(w, p, view{Error: msgLimit, Lang: lang(r, p), ReturnTo: backTo(r, t)},
			http.StatusTooManyRequests)

		return
	}

	widgets, err := s.widgets(ctx, r, p, t)
	if err != nil {
		s.fail(w, "cannot issue challenges", err)

		return
	}

	if skip != "" && len(widgets) > 1 {
		kept := widgets[:0]

		for _, wv := range widgets {
			if wv.Kind != skip {
				kept = append(kept, wv)
			}
		}

		widgets = kept
		widgets[0].Primary = true
	}

	status := http.StatusOK
	if msg != "" {
		status = http.StatusBadRequest
	}

	s.render(w, p, view{
		Nonce:    t.Nonce,
		Error:    msg,
		Attempt:  t.Attempt,
		ReturnTo: backTo(r, t),
		Lang:     lang(r, p),
		Widgets:  widgets,
	}, status)
}

func (s *server) widgets(ctx context.Context, r *http.Request, p *config.Profile,
	t *token.Ticket) ([]widgetView, error) {

	chain, err := s.chain(p, t)
	if err != nil {
		return nil, err
	}

	sess := provider.Session{
		Nonce:    t.Nonce,
		ClientIP: s.clientIP(r),
		Lang:     lang(r, p),
	}

	out := make([]widgetView, 0, len(chain))

	for i, prv := range chain {
		c, err := prv.Issue(ctx, sess)
		if err != nil {
			s.log.Warn("issue failed", "provider", prv.Kind(), "error", err.Error())
			continue
		}

		data, err := json.Marshal(c.Data)
		if err != nil {
			return nil, err
		}

		wv := widgetView{
			Kind:    c.Kind,
			Data:    templateJS(data),
			NeedJS:  c.NeedJS,
			Primary: i == 0,
		}

		if img, ok := c.Data["image"].(string); ok {
			wv.Image = template.URL(img)
		}

		if audio, ok := c.Data["audio"].(bool); ok {
			wv.Audio = audio
		}

		out = append(out, wv)
	}

	if len(out) == 0 {
		return nil, errors.New("no provider could issue a challenge")
	}

	return out, nil
}

// chain -- провайдеры для этого билета: правило страницы возврата может
// назначить свой основной виджет.
func (s *server) chain(p *config.Profile, t *token.Ticket) ([]provider.Provider, error) {
	primary := ""

	if t != nil && t.Return != "" {
		uri, _, _ := strings.Cut(t.Return, "?")
		primary = p.RuleFor(http.MethodGet, uri).Provider
	}

	return provider.Chain(p, primary, provider.Deps{Roster: s.roster, Secrets: s.secrets})
}

/* --- форма ----------------------------------------------------------------- */

func (s *server) submit(w http.ResponseWriter, r *http.Request, fallback *config.Profile) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	p, t, err := s.session(r, fallback)
	if err != nil {
		s.page(w, r, p, "")
		return
	}

	if r.PostFormValue("csrf") != t.Nonce {
		s.page(w, r, p, msgExpired)
		return
	}

	res := s.check(r.Context(), r, p, t, answerOf(r))

	switch {
	case res.ok:
		s.grant(w, r, p, t, res)
		redirectBack(w, r, backTo(r, t))

	case res.status == http.StatusTooManyRequests:
		s.render(w, p, view{Error: res.msg, Lang: lang(r, p), ReturnTo: backTo(r, t)},
			res.status)

	default:
		s.pageSkipping(w, r, p, res.msg, res.skip)
	}
}

func answerOf(r *http.Request) provider.Answer {
	return provider.Answer{Value: strings.TrimSpace(r.PostFormValue("answer"))}
}

/* --- SPA ------------------------------------------------------------------- */

func (s *server) api(w http.ResponseWriter, r *http.Request, fallback *config.Profile) {
	p, t, err := s.session(r, fallback)
	if err != nil {
		s.writeJSON(w, http.StatusForbidden, map[string]any{"error": "no_ticket"})
		return
	}

	ctx := r.Context()

	if !s.within(ctx, p.Limits.IssuePerSubnet, "issue", s.subnet(r, p)) {
		s.writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "rate_limited"})
		return
	}

	widgets, err := s.widgets(ctx, r, p, t)
	if err != nil {
		s.fail(w, "cannot issue challenges", err)
		return
	}

	list := make([]map[string]any, 0, len(widgets))

	for _, wv := range widgets {
		var data map[string]any
		_ = json.Unmarshal([]byte(wv.Data), &data)

		list = append(list, map[string]any{
			"kind": wv.Kind, "needs_js": wv.NeedJS, "data": data,
		})
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"nonce":     t.Nonce,
		"attempt":   t.Attempt,
		"verify":    strings.TrimRight(p.Path, "/") + "/" + actionVerify,
		"providers": list,
	})
}

type verifyBody struct {
	Nonce    string `json:"nonce"`
	Provider string `json:"provider"`
	Answer   string `json:"answer"`
	FP       string `json:"fp"`
}

func (s *server) verify(w http.ResponseWriter, r *http.Request, fallback *config.Profile) {
	var body verifyBody

	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&body); err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad_json"})
		return
	}

	p, t, err := s.session(r, fallback)
	if err != nil {
		s.writeJSON(w, http.StatusForbidden, map[string]any{"error": "no_ticket"})
		return
	}

	if body.Nonce != t.Nonce {
		s.writeJSON(w, http.StatusForbidden, map[string]any{"error": "expired"})
		return
	}

	res := s.check(r.Context(), r, p, t, provider.Answer{Value: strings.TrimSpace(body.Answer)},
		withKind(body.Provider), withFP(body.FP))

	if !res.ok {
		s.writeJSON(w, res.status, map[string]any{"error": res.code})
		return
	}

	s.grant(w, r, p, t, res)
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) status(w http.ResponseWriter, r *http.Request, p *config.Profile) {
	raw := cookieValue(r, p.Clearance.Cookie)
	if raw == "" {
		s.writeJSON(w, http.StatusOK, map[string]any{"cleared": false})
		return
	}

	clr, err := s.cfg.Key.OpenClearance(raw, time.Now(), s.bindOf(r, p))
	if err != nil || !s.alive(p, clr) {
		s.writeJSON(w, http.StatusOK, map[string]any{"cleared": false})
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"cleared":  true,
		"provider": clr.Provider,
		"expires":  clr.Expiry,
	})
}

/* --- проверка -------------------------------------------------------------- */

type checkResult struct {
	ok       bool
	status   int
	code     string
	msg      string
	provider string
	fp       string
	// flag -- пометка в клиренс и аудит: provider_down при on_error: allow.
	flag string
	// skip -- провайдер, который не ответил: страница покажет следующий.
	skip string
}

type checkOpt func(*checkOpts)

type checkOpts struct {
	kind string
	fp   string
}

func withKind(k string) checkOpt { return func(o *checkOpts) { o.kind = k } }
func withFP(fp string) checkOpt  { return func(o *checkOpts) { o.fp = fp } }

func (s *server) check(ctx context.Context, r *http.Request, p *config.Profile,
	t *token.Ticket, a provider.Answer, opts ...checkOpt) checkResult {

	var o checkOpts
	for _, fn := range opts {
		fn(&o)
	}

	if o.kind == "" {
		o.kind = r.PostFormValue("provider")
	}

	if o.fp == "" {
		o.fp = r.PostFormValue("fp")
	}

	subnet := s.subnet(r, p)

	if !s.within(ctx, p.Limits.VerifyPerSubnet, "verify", subnet) {
		return checkResult{status: http.StatusTooManyRequests, code: "rate_limited", msg: msgLimit}
	}

	if fp := fpHash(o.fp); fp != "" && s.roster.Revoked("fp:"+fp) {
		return checkResult{status: http.StatusTooManyRequests, code: "banned", msg: msgBanned}
	}

	chain, err := s.chain(p, t)
	if err != nil {
		s.log.Error("chain failed", "profile", p.Name, "error", err.Error())

		return checkResult{status: http.StatusInternalServerError, code: "internal", msg: msgProvider}
	}

	/*
	 * Без JS скрытые поля provider/answer пусты: ответ лежит в поле
	 * answer_<вид> того виджета, который заполнил человек.
	 */
	if a.Value == "" {
		for _, cand := range chain {
			if v := strings.TrimSpace(r.PostFormValue("answer_" + cand.Kind())); v != "" {
				o.kind = cand.Kind()
				a.Value = v

				break
			}
		}
	}

	prv := provider.ByKind(chain, o.kind)
	if prv == nil {
		prv = chain[0]
	}

	a.ClientIP = s.clientIP(r)
	sess := provider.Session{Nonce: t.Nonce, ClientIP: a.ClientIP}

	err = prv.Verify(ctx, sess, a)

	switch {
	case errors.Is(err, provider.ErrUnavailable):
		s.stats.Inc("provider." + prv.Kind() + ".down")
		s.log.Warn("provider unavailable", "provider", prv.Kind(), "profile", p.Name,
			"error", err.Error())

		/*
		 * Политика on_error профиля: fallback -- страница со следующим
		 * виджетом; allow -- клиренс без проверки, с пометкой в аудите;
		 * deny -- отказ.
		 */
		onError := config.OnErrorFallback
		if ext, ok := prv.(*provider.External); ok {
			onError = ext.OnError()
		}

		switch onError {
		case config.OnErrorAllow:
			first, berr := s.roster.Burn(ctx, "nonce", t.Nonce, p.Challenge.TTL.D())
			if berr != nil || !first {
				return checkResult{status: http.StatusForbidden, code: "replay", msg: msgExpired}
			}

			return checkResult{ok: true, provider: prv.Kind(), fp: fpHash(o.fp), flag: "provider_down"}

		case config.OnErrorDeny:
			return checkResult{status: http.StatusBadGateway, code: "provider_down", msg: msgProvider}
		}

		return checkResult{status: http.StatusBadGateway, code: "provider_down",
			msg: msgProvider, skip: prv.Kind()}

	case err != nil:
		s.stats.Inc("provider." + prv.Kind() + ".failed")

		s.log.Info("captcha failed",
			"profile", p.Name, "provider", prv.Kind(), "subnet", subnet,
			"attempt", t.Attempt)

		/*
		 * Цену провала назначают правила профиля: заряд корзины, запись в
		 * набор. Жёсткого замка подсети больше нет -- перебор виден по
		 * заполнению, и наказание за него -- тоже правило (bucket_full).
		 */
		s.fired(ctx, p, config.OnFail, a.ClientIP, "", "")

		return checkResult{status: http.StatusBadRequest, code: "wrong", msg: msgWrong}
	}

	/*
	 * Nonce сжигается после ответа провайдера, а не до: иначе неверный
	 * ответ стоил бы нового билета. Но сжигается обязательно и первым --
	 * второй POST с тем же верным ответом клиренса не получает.
	 */
	first, err := s.roster.Burn(ctx, "nonce", t.Nonce, p.Challenge.TTL.D())
	if err != nil {
		s.log.Error("burn failed", "error", err.Error())

		return checkResult{status: http.StatusInternalServerError, code: "internal", msg: msgProvider}
	}

	if !first {
		return checkResult{status: http.StatusForbidden, code: "replay", msg: msgExpired}
	}

	s.stats.Inc("provider." + prv.Kind() + ".solved")

	return checkResult{ok: true, provider: prv.Kind(), fp: fpHash(o.fp)}
}

// audio -- произнесённый текст картинки для тех, кто её не видит.
func (s *server) audio(w http.ResponseWriter, r *http.Request, fallback *config.Profile) {
	p, t, err := s.session(r, fallback)
	if err != nil {
		http.Error(w, "no ticket", http.StatusForbidden)
		return
	}

	chain, err := s.chain(p, t)
	if err != nil {
		s.fail(w, "chain failed", err)
		return
	}

	img, _ := provider.ByKind(chain, config.ProviderImage).(*provider.Image)
	if img == nil || !img.AudioEnabled() {
		http.NotFound(w, r)
		return
	}

	wav, err := img.Audio(r.Context(), t.Nonce)
	if err != nil {
		http.Error(w, "no challenge", http.StatusNotFound)
		return
	}

	s.stats.Inc("provider.image.audio")
	w.Header().Set("Content-Type", "audio/wav")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(wav)
}

// grant выписывает клиренс и короткий идентификатор, публикует в список.
func (s *server) grant(w http.ResponseWriter, r *http.Request, p *config.Profile,
	t *token.Ticket, res checkResult) {

	now := time.Now()
	bind := s.bindOf(r, p)

	clr := &token.Clearance{
		JTI:      token.NewID(),
		CID:      token.NewID(),
		Issued:   now.Unix(),
		Expiry:   now.Add(p.Clearance.TTL.D()).Unix(),
		Profile:  p.Name,
		Provider: res.provider,
		Net:      bind.Net,
		UA:       bind.UA,
		FP:       res.fp,
	}

	if res.flag != "" {
		clr.Flags = []string{res.flag}
	}

	/*
	 * Ферма: один отпечаток на много клиренсов в окне. Отпечаток уходит в
	 * множество отзыва с префиксом fp: -- инспектор сверяет с ним клиренсы,
	 * HTTP -- новые выдачи.
	 */
	if res.fp != "" && p.Fingerprint.FarmAt > 0 {
		n, err := s.roster.Fail(r.Context(), "fp:"+res.fp, p.Fingerprint.Window.D())
		if err == nil && n >= p.Fingerprint.FarmAt {
			_ = s.roster.Revoke(r.Context(), "fp:"+res.fp, now.Add(p.Clearance.TTL.D()))
			s.log.Warn("fingerprint farm", "fp", res.fp, "clearances", n, "profile", p.Name)
		}
	}

	sealed, err := s.cfg.Key.SealClearance(clr)
	if err != nil {
		s.fail(w, "cannot seal clearance", err)
		return
	}

	ttl := p.Clearance.TTL.D()

	s.setCookie(w, p.Clearance.Cookie, sealed, "/", ttl)
	s.setCookie(w, p.Clearance.IDCookie, clr.CID, "/", ttl)
	s.clearCookie(w, p.Challenge.Cookie, p.Path)

	/*
	 * Клиренс рождается записью в списке живых: список -- истина, и без
	 * записи инспектор перестанет признавать его через grace секунд. Reason
	 * несёт адрес -- запись в панели обязана читаться человеком.
	 */
	if p.Clearance.ListEnabled() && s.list != nil {
		if err := s.list.Add(p.Clearance.List, clr.JTI,
			ttl, "CAPTCHA_PASS "+s.clientIP(r)); err != nil {
			s.log.Warn("clearance list add failed", "jti", clr.JTI, "error", err.Error())
		}
	}

	/*
	 * Прошёл проверку -- правила on: pass: обелить корзину, записать в наборы.
	 * Прошедшие -- тоже правило: write: cid кладёт короткий идентификатор в
	 * названный набор, жёсткой публикации больше нет.
	 */
	s.fired(r.Context(), p, config.OnPass, s.clientIP(r), sealed, clr.CID)

	s.stats.Inc("clearance.issued")
	s.log.Info("clearance issued",
		"profile", p.Name,
		"provider", res.provider,
		"jti", clr.JTI,
		"attempt", t.Attempt,
		"client_ip", s.clientIP(r),
	)
}

/* --- лимиты ---------------------------------------------------------------- */

// within -- счётчик окна на подсеть; лимит выключен -- всегда да.
func (s *server) within(ctx context.Context, rate config.Rate, kind, subnet string) bool {
	if !rate.Enabled() {
		return true
	}

	n, err := s.roster.Fail(ctx, kind+":"+subnet, rate.Per)
	if err != nil {
		s.log.Warn("limit counter failed", "kind", kind, "error", err.Error())
		return true
	}

	return n <= rate.N
}

// fpHash -- хеш отпечатка со страницы: принимаем только hex нужной длины,
// остальное считаем отсутствием.
func fpHash(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if len(raw) != 32 {
		return ""
	}

	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return ""
		}
	}

	return raw
}
