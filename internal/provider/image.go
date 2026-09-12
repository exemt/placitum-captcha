/*
 * Image -- картинка без JS. Ответ лежит в roster под nonce билета: внешние
 * виджеты проверяет их сервер, а картинку -- мы сами, поэтому это
 * единственный провайдер с состоянием на выдаче. Каждый показ рисует новую картинку с
 * новым ответом под тем же nonce -- «другая картинка» это перезагрузка
 * страницы.
 */

package provider

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/exemt/placitum-captcha/internal/config"
	"github.com/exemt/placitum-captcha/internal/image"
	"github.com/exemt/placitum-captcha/internal/roster"
)

const imageKind = "img"

type Image struct {
	ref    config.ProviderRef
	cfg    config.ImageConfig
	ttl    time.Duration
	roster roster.Roster
}

func NewImage(ref config.ProviderRef, cfg config.ImageConfig, ttl time.Duration,
	r roster.Roster) *Image {

	return &Image{ref: ref, cfg: cfg, ttl: ttl, roster: r}
}

func (p *Image) Kind() string { return config.ProviderImage }

func (p *Image) Issue(ctx context.Context, s Session) (Challenge, error) {
	text := image.Text(p.cfg.Alphabet, p.ref.Length)

	if err := p.roster.Put(ctx, imageKind, s.Nonce, []byte(text), p.ttl); err != nil {
		return Challenge{}, err
	}

	png := image.Render(text)

	return Challenge{
		Kind:   config.ProviderImage,
		NeedJS: false,
		Data: map[string]any{
			"image":  "data:image/png;base64," + base64.StdEncoding.EncodeToString(png),
			"length": p.ref.Length,
			"audio":  p.AudioEnabled(),
		},
	}, nil
}

// AudioEnabled -- флаг профиля и наличие каталога сэмплов.
func (p *Image) AudioEnabled() bool {
	return p.ref.Audio != nil && *p.ref.Audio && image.HasSamples(p.cfg.AudioDir)
}

// Audio -- WAV с произнесённым текстом задания; nil, если задания нет.
func (p *Image) Audio(ctx context.Context, nonce string) ([]byte, error) {
	want, err := p.roster.Get(ctx, imageKind, nonce)
	if err != nil {
		return nil, err
	}

	return image.Audio(p.cfg.AudioDir, string(want))
}

func (p *Image) Verify(ctx context.Context, s Session, a Answer) error {
	want, err := p.roster.Get(ctx, imageKind, s.Nonce)
	if errors.Is(err, roster.ErrNotFound) {
		return ErrWrong
	}

	if err != nil {
		return ErrUnavailable
	}

	if !strings.EqualFold(strings.TrimSpace(a.Value), string(want)) {
		return ErrWrong
	}

	// Ответ одноразовый: повторный POST с тем же текстом не проходит даже до
	// сжигания nonce.
	_ = p.roster.Del(ctx, imageKind, s.Nonce)

	return nil
}
