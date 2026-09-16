package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/exemt/placitum-captcha/internal/config"
	"github.com/exemt/placitum-captcha/internal/decide"
	"github.com/exemt/placitum-captcha/internal/protocol"
)

const (
	formMax     = 1 << 20
	formTTL     = 15 * time.Second
	formSuffix  = "form"
	formTimeout = 2 * time.Second
)

var errNoHTTP = errors.New("WAF_CAPTCHA_HTTP_URL is empty")

type formFetcher struct {
	client *http.Client
	base   string
}

func newFormFetcher(base string) *formFetcher {
	return &formFetcher{
		client: &http.Client{
			Timeout: formTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		base: base,
	}
}

func (h *handler) inlineForm(ctx context.Context, req *protocol.Request,
	p *config.Profile, res decide.Result, userAgent string) (*protocol.Rewrite, error) {

	if h.forms == nil {
		return nil, errNoHTTP
	}

	ticket := cookieOf(res.Cookies, p.Challenge.Cookie)
	if ticket == "" {
		return nil, errors.New("no ticket in the result")
	}

	ctx, cancel := context.WithTimeout(ctx, formTimeout)
	defer cancel()

	body, ctype, err := h.forms.page(ctx, p.Path, p.Challenge.Cookie+"="+ticket,
		req.Conn.ClientIP, userAgent)
	if err != nil {
		return nil, err
	}

	key := req.Node + ":" + req.RID + ":req:" + formSuffix

	if err := h.store.Put(ctx, key, body, formTTL); err != nil {
		return nil, fmt.Errorf("store put: %w", err)
	}

	sum := sha256.Sum256(body)

	return &protocol.Rewrite{
		Body: &protocol.RewriteBody{
			Key:    key,
			Size:   int64(len(body)),
			SHA256: hex.EncodeToString(sum[:]),
		},
		ContentType: ctype,
	}, nil
}

func (f *formFetcher) page(ctx context.Context, path, cookie, clientIP,
	userAgent string) ([]byte, string, error) {

	r, err := http.NewRequestWithContext(ctx, http.MethodGet, f.base+path, nil)
	if err != nil {
		return nil, "", err
	}

	r.Header.Set("Cookie", cookie)
	r.Header.Set("X-Forwarded-For", clientIP)
	r.Header.Set("Accept", "text/html")

	if userAgent != "" {
		r.Header.Set("User-Agent", userAgent)
	}

	resp, err := f.client.Do(r)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("captcha-http answered %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, formMax+1))
	if err != nil {
		return nil, "", err
	}

	if len(body) > formMax {
		return nil, "", fmt.Errorf("page exceeds %d bytes", formMax)
	}

	ctype := resp.Header.Get("Content-Type")
	if ctype == "" || strings.ContainsAny(ctype, "\r\n") {
		ctype = "text/html; charset=utf-8"
	}

	return body, ctype, nil
}

func cookieOf(cookies []protocol.Cookie, name string) string {
	for _, c := range cookies {
		if c.Name == name {
			return c.Value
		}
	}

	return ""
}
