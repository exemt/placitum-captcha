package config

import (
	"fmt"
	"html/template"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/exemt/placitum-captcha/internal/overload"
	"github.com/exemt/placitum-captcha/internal/protocol"
)

const (
	ModeEnforce = "enforce"
	ModeObserve = "observe"
	ModeOff     = "off"

	WhenAlways  = "always"
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

	AnyInspector = "*"
)

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
	Name string `yaml:"-"`

	Mode  string `yaml:"mode"`
	Path  string `yaml:"path"`
	Title string `yaml:"title"`
	Note  string `yaml:"note"`

	Trigger     Trigger        `yaml:"trigger"`
	Buckets     Buckets        `yaml:"buckets"`
	Rules       []EventRule    `yaml:"rules"`
	Pages       []PageRule     `yaml:"pages"`
	Gate        Gate           `yaml:"gate"`
	Provider    ProviderRef    `yaml:"provider"`
	Fallback    *ProviderRef   `yaml:"fallback"`
	ProviderCfg ProviderConfig `yaml:"provider_config"`
	Challenge   Challenge      `yaml:"challenge"`
	Clearance   Clearance      `yaml:"clearance"`
	Fingerprint FingerprintCfg `yaml:"fingerprint"`
	Limits      Limits         `yaml:"limits"`
	Upstream    Upstream       `yaml:"upstream"`
	Roster      Roster         `yaml:"roster"`
	Languages   []string       `yaml:"languages"`

	Page *template.Template `yaml:"-"`
}

type Buckets struct {
	IP        BucketTier `yaml:"ip"`
	Sess      BucketTier `yaml:"sess"`
	ASNNet    BucketTier `yaml:"asn_net"`
	ASNRouter BucketTier `yaml:"asn_router"`
}

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

func (b Buckets) Enabled() bool {
	return b.IP.Enabled() || b.Sess.Enabled() || b.ASNNet.Enabled() ||
		b.ASNRouter.Enabled()
}

type BucketTier struct {
	Max       float64 `yaml:"max"`
	Loss      float64 `yaml:"loss"`
	CaptchaAt int     `yaml:"captcha_at"`
	BanAt     int     `yaml:"ban_at"`
}

func (t BucketTier) Enabled() bool { return t.Max > 0 && t.Loss > 0 }

var codeRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

var counterNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

const (
	OnFail          = "fail"
	OnPass          = "pass"
	OnBucketCaptcha = "bucket_captcha"
	OnBucketBan     = "bucket_ban"
	OnCleared       = "cleared"
	OnUncleared     = "uncleared"
	OnOverload      = overload.On
)

func onWave(on string) bool {
	return on == OnBucketCaptcha || on == OnBucketBan || on == OnCleared || on == OnUncleared ||
		on == OnOverload
}

func bucketEvent(on string) bool {
	return on == OnBucketCaptcha || on == OnBucketBan
}

const (
	NextAllow     = "allow"
	NextChallenge = "challenge"
)

func nextEvent(on string) bool {
	return on == OnUncleared || bucketEvent(on)
}

const (
	WriteAddr   = "addr"
	WriteNet    = "net"
	WriteNetAll = "net_all"
	WriteASN    = "asn"
	WriteCID    = "cid"
)

type EventRule struct {
	On     string `yaml:"on"`
	At     *int   `yaml:"at"`
	Bucket string `yaml:"bucket"`
	Next   string `yaml:"next"`

	To      string               `yaml:"to"`
	Do      string               `yaml:"do"`
	Apply   string               `yaml:"apply"`
	Phase   string               `yaml:"phase"`
	Delta   *int                 `yaml:"delta"`
	Value   *int                 `yaml:"value"`
	Counter string               `yaml:"counter"`
	Group   string               `yaml:"group"`
	Set     string               `yaml:"set"`
	Marker  string               `yaml:"marker"`
	Headers *protocol.ObjectSpec `yaml:"headers"`
	Args    *protocol.ObjectSpec `yaml:"args"`
	Body    *protocol.ObjectSpec `yaml:"body"`
	When    []string             `yaml:"when"`

	List  string   `yaml:"list"`
	TTL   Duration `yaml:"ttl"`
	Write string   `yaml:"write"`

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
		if r.At != nil {
			return fmt.Errorf("%s: at is only for on: %s", at, OnOverload)
		}

	case OnOverload:
		if err := overload.Check(r.At); err != nil {
			return fmt.Errorf("%s: %w", at, err)
		}

	default:
		return fmt.Errorf("%s: on must be fail, pass, bucket_captcha, "+
			"bucket_ban, cleared, uncleared or overload, got %q", at, r.On)
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
		axes = []string{protocol.ApplyRequest}

	case protocol.DoAudit, protocol.DoArchive:
		axes = []string{protocol.ApplyRequest}

	case protocol.DoMark, protocol.DoScore:
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

	if controlVerb(r.Do) && r.To == "" {
		return fmt.Errorf("%s: %s needs to: the module switches one call, not everyone", at, r.Do)
	}

	if err := checkPhaseAsk(r.Do, r.Phase, r.Axis()); err != nil {
		return fmt.Errorf("%s: %w", at, err)
	}

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

		if r.Counter != "" && !counterNameRe.MatchString(r.Counter) {
			return fmt.Errorf("%s: bad counter name %q", at, r.Counter)
		}

	case protocol.DoScore:
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

	if r.Do == protocol.DoMark {
		if err := protocol.CheckMarker(r.Marker); err != nil {
			return fmt.Errorf("%s: %w", at, err)
		}
	} else if r.Marker != "" {
		return fmt.Errorf("%s: marker is only for mark", at)
	}

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

func auditVerb(do string) bool {
	return do == protocol.DoAudit || do == protocol.DoArchive
}

func recordVerb(do string) bool {
	return auditVerb(do) || do == protocol.DoMark || do == protocol.DoScore
}

func controlVerb(do string) bool {
	switch do {
	case protocol.DoActive, protocol.DoPassive, protocol.DoVote, protocol.DoOff:
		return true
	}

	return false
}

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

func (r EventRule) Axis() string {
	if r.Apply != "" {
		return r.Apply
	}

	switch r.Do {
	case protocol.DoReauth:
		return protocol.ApplySession

	case protocol.DoNote:
		return ""
	}

	return protocol.ApplyRequest
}

func (p *Profile) RulesFor(on, bucket, next string) []EventRule {
	var out []EventRule

	for _, r := range p.Rules {
		if r.On != on {
			continue
		}

		if r.Bucket != "" && r.Bucket != bucket {
			continue
		}

		if r.Next != "" && r.Next != next {
			continue
		}

		out = append(out, r)
	}

	return out
}

type Trigger struct {
	When  string      `yaml:"when"`
	Prior []PriorRule `yaml:"prior"`
}

type PriorRule struct {
	From   string   `yaml:"from"`
	Accept []string `yaml:"accept"`
	Codes  []string `yaml:"codes"`
}

const AnyVerb = "*"

var captchaVerbs = []string{
	protocol.DoChallenge, protocol.DoThreshold, protocol.DoSkip, protocol.DoNote,
}

func (r PriorRule) Accepts(verb string) bool {
	for _, v := range r.Accept {
		if v == verb || v == AnyVerb {
			return true
		}
	}

	return false
}

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

type PageRule struct {
	Path     string   `yaml:"path"`
	Match    string   `yaml:"match"`
	Methods  []string `yaml:"methods"`
	When     string   `yaml:"when"`
	Provider string   `yaml:"provider"`
}

type Gate struct {
	RedirectMethods []string `yaml:"redirect_methods"`
	RedirectStatus  int      `yaml:"redirect_status"`
	DenyResponse    string   `yaml:"deny_response"`
	HTMLOnly        bool     `yaml:"html_only"`

	Inline bool `yaml:"inline"`
}

type ProviderRef struct {
	Kind   string `yaml:"kind"`
	Length int    `yaml:"length"`
	Audio  *bool  `yaml:"audio"`
}

type ProviderConfig struct {
	Image        ImageConfig    `yaml:"image"`
	Turnstile    ExternalConfig `yaml:"turnstile"`
	ReCAPTCHA    ExternalConfig `yaml:"recaptcha"`
	HCaptcha     ExternalConfig `yaml:"hcaptcha"`
	SmartCaptcha ExternalConfig `yaml:"smartcaptcha"`
}

type ImageConfig struct {
	Alphabet  string   `yaml:"alphabet"`
	Languages []string `yaml:"languages"`
	AudioDir  string   `yaml:"audio_dir"`
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

	List  string   `yaml:"list"`
	Grace Duration `yaml:"grace"`
}

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

type Limits struct {
	IssuePerSubnet  Rate `yaml:"issue_per_subnet"`
	VerifyPerSubnet Rate `yaml:"verify_per_subnet"`
	PendingMax      int  `yaml:"pending_max"`
	ProviderBudget  Rate `yaml:"provider_budget"`
}

type Upstream struct {
	Header string `yaml:"header"`
}

type Roster struct {
	Store         string   `yaml:"store"`
	Prefix        string   `yaml:"prefix"`
	RevokeRefresh Duration `yaml:"revoke_refresh"`
}

func defaults(name string) *Profile {
	return &Profile{
		Name:  name,
		Mode:  ModeEnforce,
		Title: "Confirm you are not a robot",
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
		Limits: Limits{
			IssuePerSubnet:  Rate{N: 30, Per: time.Minute},
			VerifyPerSubnet: Rate{N: 60, Per: time.Minute},
			PendingMax:      200000,
			ProviderBudget:  Rate{N: 50, Per: time.Second},
		},
		Upstream: Upstream{Header: "X-WAF-Captcha"},
		Roster: Roster{
			Store:         RosterRedis,
			Prefix:        "cap:",
			RevokeRefresh: Duration(2 * time.Second),
		},
		Languages: []string{"en", "ru"},
	}
}

func ParseProfile(name string, raw []byte) (*Profile, error) {
	p := defaults(name)

	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)

	if err := dec.Decode(p); err != nil {
		return nil, fmt.Errorf("profile %s: %w", name, err)
	}

	p.Name = name

	p.Provider = providerDefaults(p.Provider)

	if p.Fallback != nil {
		f := providerDefaults(*p.Fallback)
		p.Fallback = &f
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

func (p *Profile) probeVariant() *Profile {
	c := *p
	c.Name = ProbeName
	c.Mode = ModeEnforce
	c.Trigger = Trigger{When: WhenAlways}
	c.Pages = nil

	c.Gate.HTMLOnly = false

	if c.Path == "" {
		c.Path = "/waf/captcha"
	}

	return &c
}

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

func (p *Profile) ProviderRef(kind string) *ProviderRef {
	if p.Provider.Kind == kind {
		return &p.Provider
	}

	if p.Fallback != nil && p.Fallback.Kind == kind {
		return p.Fallback
	}

	return nil
}

func (p *Profile) RedirectsMethod(method string) bool {
	for _, m := range p.Gate.RedirectMethods {
		if m == method {
			return true
		}
	}

	return false
}

func (p *Profile) FormInline() bool { return p.Gate.Inline }

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

type Rule struct {
	When     string
	Page     string
	Provider string
}

func (p *Profile) RuleFor(method, uri string) Rule {
	for _, r := range p.Pages {
		if !r.matches(method, uri) {
			continue
		}

		return Rule{When: r.When, Page: r.Path, Provider: r.Provider}
	}

	return Rule{When: p.Trigger.When}
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

func (p *Profile) BindsNet() bool { return p.hasBind(BindNet) || p.hasBind(BindIP) }
func (p *Profile) BindsUA() bool  { return p.hasBind(BindUA) }

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

func (p *Profile) ProviderKinds() []string {
	out := make([]string, 0, 2)

	for _, ref := range p.Refs() {
		out = append(out, ref.Kind)
	}

	return out
}
