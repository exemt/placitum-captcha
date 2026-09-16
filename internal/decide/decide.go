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

const (
	CodeOK                 = "CAPTCHA_OK"
	CodeOff                = "CAPTCHA_OFF"
	CodeSelf               = "CAPTCHA_SELF"
	CodeObserve            = "CAPTCHA_OBSERVE"
	CodeNotRequired        = "CAPTCHA_NOT_REQUIRED"
	CodeRequired           = "CAPTCHA_REQUIRED"
	CodeReverify           = "CAPTCHA_REVERIFY"
	CodeExhausted          = "CAPTCHA_EXHAUSTED"
	CodeClearanceBad       = "CAPTCHA_CLEARANCE_BAD"
	CodeClearanceExpired   = "CAPTCHA_CLEARANCE_EXPIRED"
	CodeClearanceBind      = "CAPTCHA_CLEARANCE_BIND"
	CodeClearanceRevoked   = "CAPTCHA_CLEARANCE_REVOKED"
	CodeListUnavailable    = "CAPTCHA_LIST_UNAVAILABLE"
	CodeStoreUnavailable   = "CAPTCHA_STORE_UNAVAILABLE"
	CodeBucketsUnavailable = "CAPTCHA_BUCKETS_UNAVAILABLE"
	CodeGeoUnavailable     = "CAPTCHA_GEO_UNAVAILABLE"
	CodeUnknownProfile     = "CAPTCHA_UNKNOWN_PROFILE"
	CodeWrongPhase         = "CAPTCHA_PHASE_NOT_SUPPORTED"
)

const (
	FindingClearanceBad     = "captcha-clearance-bad"
	FindingClearanceRevoked = "captcha-clearance-revoked"
	FindingExhausted        = "captcha-exhausted"
	FindingUnknownProfile   = "captcha-unknown-profile"
	FindingStore            = "captcha-store-unavailable"
	FindingListDown         = "captcha-list-unavailable"
)

const (
	TriggerAlways   = "always"
	TriggerPrior    = "prior"
	TriggerReverify = "reverify"
	TriggerHot      = "hot"
)

type Revoked interface {
	Revoked(id string) bool
}

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

	SecFetchDest string

	UpgradeInsecure bool

	Asked Asked

	Levels map[string]float64

	StoreUnavailable string

	Opened *Opened

	Now time.Time
}

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

	Inline bool

	Cookies []protocol.Cookie
	Headers map[string]string

	Clearance *token.Clearance
	Trigger   string
	Findings  []audit.Finding
	Engine    map[string]any

	Event string

	Next string
}

func Check(in Input, key *token.Key, revoked Revoked, clearances Clearances) (out Result) {
	defer func() {
		out.Event = eventOf(in, out)
		out.Next = nextOf(out)
	}()

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

	if p.Mode == config.ModeObserve {
		engine["passive"] = true
	}

	if in.StoreUnavailable != "" {
		engine["store"] = in.StoreUnavailable
	}

	if p.Mode == config.ModeOff {
		return allow(p, nil, CodeOff, engine)
	}

	if p.OwnPath(in.URI) {
		engine["self"] = true

		return allow(p, nil, CodeSelf, engine)
	}

	asked := in.Asked

	if len(asked.Outcomes) != 0 {
		engine["actions"] = asked.Outcomes
	}

	if len(in.Levels) != 0 {
		engine["buckets"] = in.Levels
	}

	op := in.Opened
	if op == nil {
		o := Open(in, key, revoked, clearances)
		op = &o
	}

	clr, code, finding := op.Clearance, op.Code, op.Findings

	if code == CodeListUnavailable {
		return Result{
			Verdict:  protocol.VerdictError,
			Code:     code,
			Findings: finding,
			Engine:   engine,
		}
	}

	if clr != nil {
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

	if p.Mode == config.ModeObserve {
		engine["would_verdict"] = wouldBe(in, p)
		engine["would_code"] = code

		res := allow(p, nil, CodeObserve, engine)
		res.Findings = finding
		res.Trigger = trigger

		return res
	}

	attempt := attemptOf(in, p, key)
	engine["attempt"] = attempt

	ticket := issueTicket(in, p, key, rule, attempt)

	if navigational(in, p) {
		res := redirect(in, p, ticket, code)

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

	if in.Clearance == "" && in.StoreUnavailable != "" {
		return ""
	}

	return config.OnUncleared
}

func nextOf(res Result) string {
	switch {
	case res.Trigger != "":
		return config.NextChallenge

	case res.Verdict == protocol.VerdictAllow && res.Code != CodeOff && res.Code != CodeSelf:
		return config.NextAllow
	}

	return ""
}

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

	if revoked != nil && clr.FP != "" && revoked.Revoked("fp:"+clr.FP) {
		return nil, CodeClearanceRevoked, bad(FindingClearanceRevoked, "fp:"+clr.FP)
	}

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

func bucketFull(in Input, p *config.Profile, kind string) bool {
	at := p.Buckets.Tier(kind).CaptchaAt

	if at <= 0 {
		return false
	}

	level, ok := in.Levels[kind]

	return ok && level >= float64(at)
}

func hotBuckets(in Input, p *config.Profile) []string {
	var out []string

	for _, kind := range []string{buckets.KindIP, buckets.KindNet, buckets.KindRouter} {
		if bucketFull(in, p, kind) {
			out = append(out, kind)
		}
	}

	return out
}

func required(in Input, p *config.Profile, rule config.Rule, hadClearance bool,
	ask Asked) string {

	if hadClearance {
		return TriggerReverify
	}

	if ask.Skip {
		return ""
	}

	switch rule.When {
	case config.WhenNever:
		return ""

	case config.WhenAlways:
		return TriggerAlways
	}

	if len(hotBuckets(in, p)) > 0 {
		return TriggerHot
	}

	if ask.Want {
		return TriggerPrior
	}

	return ""
}

type Asked struct {
	Want  bool
	Skip  bool
	Notes []Note

	Outcomes []ActionOutcome
}

type Note struct {
	Axis    string
	Percent int
	Code    string
}

const (
	OutcomeApplied   = "applied"
	OutcomeNoRule    = "no_rule"
	OutcomeNoCounter = "no_counter"
	OutcomeCleared   = "cleared"
)

type ActionOutcome struct {
	From  string `json:"from"`
	Do    string `json:"do"`
	Apply string `json:"apply"`
	Code  string `json:"code,omitempty"`
	Value int    `json:"value,omitempty"`
	Delta int    `json:"delta,omitempty"`

	Took    float64 `json:"took,omitempty"`
	Outcome string  `json:"outcome"`
}

func PriorAsk(prior []protocol.PriorVerdict, p *config.Profile) Asked {
	var a Asked

	if p == nil {
		return a
	}

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

func (a *Asked) take(act protocol.Action, p *config.Profile, out *ActionOutcome) {
	switch act.Do {
	case protocol.DoChallenge:
		a.Want = true
		out.apply(0)

	case protocol.DoSkip:
		a.Skip = true
		out.apply(0)

	case protocol.DoThreshold:
		out.noCounter()

	case protocol.DoNote:
		a.note(act, p, out)
	}
}

func (a *Asked) cleared() {
	for i := range a.Outcomes {
		out := &a.Outcomes[i]

		if out.Do == protocol.DoChallenge && out.Outcome == OutcomeApplied {
			out.Outcome = OutcomeCleared
		}
	}
}

func (o *ActionOutcome) apply(took float64) {
	o.Outcome = OutcomeApplied
	o.Took += took
}

func (o *ActionOutcome) noCounter() {
	if o.Outcome == OutcomeNoRule {
		o.Outcome = OutcomeNoCounter
	}
}

func (a *Asked) note(act protocol.Action, p *config.Profile, out *ActionOutcome) {
	if act.Value == 0 {
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

func showsPage(in Input) bool {
	switch in.SecFetchDest {
	case "":
		return in.UpgradeInsecure || acceptsHTML(in.Accept)
	case "document", "iframe", "frame":
		return true
	default:
		return false
	}
}

func acceptsHTML(accept string) bool {
	return strings.Contains(accept, "text/html") ||
		strings.Contains(accept, "application/xhtml+xml")
}

func wouldBe(in Input, p *config.Profile) string {
	if navigational(in, p) {
		return protocol.VerdictRedirect
	}

	return protocol.VerdictDeny
}

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
