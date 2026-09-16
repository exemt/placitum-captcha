package main

import (
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/exemt/placitum-captcha/internal/buckets"
	"github.com/exemt/placitum-captcha/internal/config"
	"github.com/exemt/placitum-captcha/internal/livelist"
	"github.com/exemt/placitum-captcha/internal/provider"
	"github.com/exemt/placitum-captcha/internal/roster"
	"github.com/exemt/placitum-captcha/internal/stats"
	"github.com/exemt/placitum-captcha/internal/token"
	"github.com/exemt/placitum-shared/dataset"
	"github.com/exemt/placitum-shared/netinfo"
)

const (
	actionPage   = ""
	actionAPI    = "api"
	actionVerify = "verify"
	actionStatus = "status"
	actionScript = "c.js"
	actionAudio  = "audio"
	actionHealth = "healthz"
)

type server struct {
	cfg        *config.Config
	log        *slog.Logger
	profiles   *config.Store
	roster     roster.Roster
	pages      *pages
	list       *dataset.Publisher
	clearances *livelist.Mirror
	secrets    provider.Secrets
	stats      *stats.Counters
	buckets    *buckets.Store
	resolver   *netinfo.Resolver
}

func (s *server) alive(p *config.Profile, clr *token.Clearance) bool {
	if !p.Clearance.ListEnabled() {
		return true
	}

	if time.Since(time.Unix(clr.Issued, 0)) <= p.Clearance.Grace.D() {
		return true
	}

	if s.clearances == nil {
		return false
	}

	listed, ready := s.clearances.Contains(p.Clearance.List, clr.JTI)

	return ready && listed
}

type pages struct {
	captcha *template.Template
	script  []byte
}

func loadPages(dir string) (*pages, error) {
	t, err := template.ParseFiles(path.Join(dir, "captcha.html"))
	if err != nil {
		return nil, err
	}

	js, err := os.ReadFile(path.Join(dir, "c.js"))
	if err != nil {
		return nil, err
	}

	return &pages{captcha: t, script: js}, nil
}

type widgetView struct {
	Kind    string
	Data    template.JS
	NeedJS  bool
	Primary bool
	Image   template.URL
	Audio   bool
}

type view struct {
	Title     string
	Note      string
	Action    string
	ScriptURL string
	Nonce     string
	Error     string
	Attempt   int
	ReturnTo  string
	Lang      string
	Collect   bool
	Canvas    bool
	Widgets   []widgetView
	NoTicket  bool
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	snap := s.profiles.Current()
	p, action := route(snap, r.URL.Path)

	if p == nil {
		http.NotFound(w, r)
		return
	}

	switch action {
	case actionHealth:
		w.WriteHeader(http.StatusNoContent)

	case actionScript:
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write(s.pages.script)

	case actionPage:
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			s.page(w, r, p, "")
		case http.MethodPost:
			s.submit(w, r, p)
		default:
			w.Header().Set("Allow", "GET, HEAD, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}

	case actionAPI:
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		s.api(w, r, p)

	case actionVerify:
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		s.verify(w, r, p)

	case actionStatus:
		s.status(w, r, p)

	case actionAudio:
		s.audio(w, r, p)

	default:
		http.NotFound(w, r)
	}
}

func route(snap *config.Snapshot, uri string) (*config.Profile, string) {
	for _, p := range snap.All() {
		if p.Path == "" {
			continue
		}

		if uri == p.Path {
			return p, actionPage
		}

		prefix := strings.TrimRight(p.Path, "/") + "/"
		if strings.HasPrefix(uri, prefix) {
			return p, strings.TrimPrefix(uri, prefix)
		}
	}

	return nil, ""
}

func (s *server) session(r *http.Request, fallback *config.Profile) (
	*config.Profile, *token.Ticket, error) {

	raw := cookieValue(r, fallback.Challenge.Cookie)
	if raw == "" {
		return fallback, nil, errNoTicket
	}

	t, err := s.cfg.Key.OpenTicket(raw, time.Now())
	if err != nil {
		return fallback, nil, errNoTicket
	}

	p, ok := s.profiles.Current().Profile(t.Profile)
	if !ok {
		return fallback, nil, errNoTicket
	}

	want := s.bindOf(r, p)

	if (want.Net != "" && t.Net != "" && want.Net != t.Net) ||
		(want.UA != "" && t.UA != "" && want.UA != t.UA) {
		return p, t, errBind
	}

	return p, t, nil
}

var (
	errNoTicket = errors.New("no ticket")
	errBind     = errors.New("ticket binding mismatch")
)

func (s *server) setCookie(w http.ResponseWriter, name, value, path string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *server) clearCookie(w http.ResponseWriter, name, path string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     path,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *server) bindOf(r *http.Request, p *config.Profile) token.Bind {
	var b token.Bind

	if p.BindsNet() {
		v4, v6 := p.NetBits()
		b.Net = token.Subnet(s.clientIP(r), v4, v6)
	}

	if p.BindsUA() {
		b.UA = token.Fingerprint(r.Header.Get("User-Agent"))
	}

	return b
}

func (s *server) clientIP(r *http.Request) string {
	return forwardedAddr(r.Header.Values(s.cfg.RealIPHeader), r.RemoteAddr)
}

func forwardedAddr(values []string, remoteAddr string) string {
	if n := len(values); n > 0 {
		last := values[n-1]

		if i := strings.LastIndexByte(last, ','); i >= 0 {
			last = last[i+1:]
		}

		if ip := strings.TrimSpace(last); net.ParseIP(ip) != nil {
			return ip
		}
	}

	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}

	return host
}

func (s *server) subnet(r *http.Request, p *config.Profile) string {
	return token.Subnet(s.clientIP(r), p.Clearance.Subnet.V4, p.Clearance.Subnet.V6)
}

func backTo(r *http.Request, t *token.Ticket) string {
	if t != nil && t.Return != "" {
		return t.Return
	}

	if back := localPath(r.URL.Query().Get("rd")); back != "" {
		return back
	}

	return "/"
}

func (s *server) render(w http.ResponseWriter, p *config.Profile, v view, status int) {
	v.Title = p.Title
	v.Note = p.Note
	v.Action = p.Path
	v.ScriptURL = strings.TrimRight(p.Path, "/") + "/" + actionScript
	v.Collect = p.Fingerprint.Collect
	v.Canvas = p.Fingerprint.Canvas

	if v.Lang == "" {
		v.Lang = "en"
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(status)

	page := s.pages.captcha
	if p.Page != nil {
		page = p.Page
	}

	if err := page.Execute(w, v); err != nil {
		s.log.Error("render failed", "profile", p.Name, "error", err.Error())
	}
}

func (s *server) writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(body)
}

func (s *server) fail(w http.ResponseWriter, what string, err error) {
	s.log.Error(what, "error", err.Error())
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func templateJS(b []byte) template.JS { return template.JS(b) }

func cookieValue(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}

	return c.Value
}

func lang(r *http.Request, p *config.Profile) string {
	accept := strings.ToLower(r.Header.Get("Accept-Language"))

	for _, part := range strings.Split(accept, ",") {
		code, _, _ := strings.Cut(strings.TrimSpace(part), ";")
		code, _, _ = strings.Cut(code, "-")

		for _, known := range p.Languages {
			if code == known {
				return code
			}
		}
	}

	if len(p.Languages) > 0 {
		return p.Languages[0]
	}

	return "en"
}

func localPath(raw string) string {
	const max = 1024

	if raw == "" || raw[0] != '/' || strings.HasPrefix(raw, "//") || len(raw) > max {
		return ""
	}

	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c < 0x21 || c > 0x7e || c == '\\' {
			return ""
		}
	}

	return raw
}

func redirectBack(w http.ResponseWriter, r *http.Request, back string) {
	if u, err := url.Parse(back); err != nil || u.IsAbs() {
		back = "/"
	}

	http.Redirect(w, r, back, http.StatusSeeOther)
}
