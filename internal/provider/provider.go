package provider

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/exemt/placitum-captcha/internal/config"
	"github.com/exemt/placitum-captcha/internal/roster"
)

var (
	ErrWrong       = errors.New("answer is wrong")
	ErrUnavailable = errors.New("provider is unavailable")
)

type Session struct {
	Nonce    string
	ClientIP string
	Lang     string
}

type Challenge struct {
	Kind   string
	Data   map[string]any
	NeedJS bool
}

type Answer struct {
	Value    string
	ClientIP string
}

type Provider interface {
	Kind() string
	Issue(ctx context.Context, s Session) (Challenge, error)
	Verify(ctx context.Context, s Session, a Answer) error
}

type Deps struct {
	Roster  roster.Roster
	Secrets Secrets
}

func Chain(p *config.Profile, primary string, deps Deps) ([]Provider, error) {
	refs := p.Refs()

	if primary != "" && primary != p.Provider.Kind {
		if ref := p.ProviderRef(primary); ref != nil {
			refs = []config.ProviderRef{*ref}

			if p.Fallback != nil && p.Fallback.Kind != primary {
				refs = append(refs, *p.Fallback)
			} else {
				refs = append(refs, p.Provider)
			}
		}
	}

	out := make([]Provider, 0, len(refs))

	for _, ref := range refs {
		switch ref.Kind {
		case config.ProviderImage:
			out = append(out, NewImage(ref, p.ProviderCfg.Image,
				time.Duration(p.Challenge.TTL), deps.Roster))

		case config.ProviderTurnstile, config.ProviderReCAPTCHA,
			config.ProviderHCaptcha, config.ProviderSmartCaptcha:
			out = append(out, NewExternal(ref.Kind, p.External(ref.Kind), deps.Secrets))

		default:
			return nil, fmt.Errorf("provider %q is not implemented", ref.Kind)
		}
	}

	if len(out) == 0 {
		return nil, errors.New("no providers")
	}

	return out, nil
}

func ByKind(chain []Provider, kind string) Provider {
	for _, p := range chain {
		if p.Kind() == kind {
			return p
		}
	}

	return nil
}
