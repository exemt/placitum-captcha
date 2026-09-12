/*
 * Внешние виджеты: Turnstile, reCAPTCHA, hCaptcha, SmartCaptcha. Страница
 * грузит скрипт провайдера и отдаёт его токен; HTTP сверяет токен через
 * siteverify своим секретом. Секрет -- из переменной окружения либо из
 * store-объекта контура; в браузер и в профиль на ноде он не попадает.
 *
 * Сеть недоступна или провайдер отвечает не тем -- ErrUnavailable, дальше
 * решает on_error профиля. Ответ "success: false" -- ErrWrong.
 */

package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/exemt/placitum-captcha/internal/config"
)

// Secrets открывает store-объекты; nil -- ссылки store: не открываются.
type Secrets interface {
	Get(ctx context.Context, id string) (string, error)
}

type External struct {
	kind    string
	cfg     config.ExternalConfig
	secrets Secrets
	client  *http.Client
}

func NewExternal(kind string, cfg config.ExternalConfig, sec Secrets) *External {
	return &External{
		kind:    kind,
		cfg:     cfg,
		secrets: sec,
		client:  &http.Client{Timeout: cfg.Timeout.D()},
	}
}

func (p *External) Kind() string { return p.kind }

// OnError -- политика профиля при недоступности; HTTP читает её отсюда,
// чтобы не лезть в конфиг по виду.
func (p *External) OnError() string { return p.cfg.OnError }

func (p *External) Issue(_ context.Context, _ Session) (Challenge, error) {
	data := map[string]any{"sitekey": p.cfg.SiteKey}

	if p.kind == config.ProviderReCAPTCHA {
		data["version"] = p.cfg.Version
	}

	return Challenge{Kind: p.kind, NeedJS: true, Data: data}, nil
}

func (p *External) secret(ctx context.Context) (string, error) {
	if p.cfg.SecretEnv != "" {
		v := os.Getenv(p.cfg.SecretEnv)
		if v == "" {
			return "", fmt.Errorf("%s: %s is empty", p.kind, p.cfg.SecretEnv)
		}

		return v, nil
	}

	if p.secrets == nil {
		return "", fmt.Errorf("%s: secret_store is set but the contour key is not loaded", p.kind)
	}

	return p.secrets.Get(ctx, p.cfg.SecretStore)
}

func (p *External) Verify(ctx context.Context, _ Session, a Answer) error {
	if a.Value == "" {
		return ErrWrong
	}

	secret, err := p.secret(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}

	switch p.kind {
	case config.ProviderSmartCaptcha:
		return p.smartcaptcha(ctx, secret, a)
	default:
		return p.siteverify(ctx, secret, a)
	}
}

var verifyURL = map[string]string{
	config.ProviderTurnstile: "https://challenges.cloudflare.com/turnstile/v0/siteverify",
	config.ProviderReCAPTCHA: "https://www.google.com/recaptcha/api/siteverify",
	config.ProviderHCaptcha:  "https://api.hcaptcha.com/siteverify",
}

type siteverifyReply struct {
	Success    bool     `json:"success"`
	Score      float64  `json:"score"`
	ErrorCodes []string `json:"error-codes"`
}

func (p *External) siteverify(ctx context.Context, secret string, a Answer) error {
	form := url.Values{"secret": {secret}, "response": {a.Value}}

	if p.cfg.RemoteIP && a.ClientIP != "" {
		form.Set("remoteip", a.ClientIP)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, verifyURL[p.kind],
		strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var reply siteverifyReply
	if err := p.do(req, &reply); err != nil {
		return err
	}

	if !reply.Success {
		return ErrWrong
	}

	if p.kind == config.ProviderReCAPTCHA && p.cfg.Version == "v3" && reply.Score < p.cfg.MinScore {
		return ErrWrong
	}

	return nil
}

func (p *External) smartcaptcha(ctx context.Context, secret string, a Answer) error {
	q := url.Values{"secret": {secret}, "token": {a.Value}}

	if p.cfg.RemoteIP && a.ClientIP != "" {
		q.Set("ip", a.ClientIP)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://smartcaptcha.yandexcloud.net/validate?"+q.Encode(), nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}

	var reply struct {
		Status string `json:"status"`
	}

	if err := p.do(req, &reply); err != nil {
		return err
	}

	if reply.Status != "ok" {
		return ErrWrong
	}

	return nil
}

func (p *External) do(req *http.Request, out any) error {
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil || resp.StatusCode >= 500 {
		return fmt.Errorf("%w: status %d", ErrUnavailable, resp.StatusCode)
	}

	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("%w: malformed reply", ErrUnavailable)
	}

	return nil
}

// Unavailable -- удобная проверка для HTTP.
func Unavailable(err error) bool { return errors.Is(err, ErrUnavailable) }
