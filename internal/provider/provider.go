/*
 * Провайдер -- способ показать задание и проверить ответ. Контракт узкий и
 * одинаковый для картинки и внешних виджетов: выдать задание под
 * сессию, принять ответ, сказать да или нет. Инспектор провайдеров не знает
 * вовсе -- только HTTP.
 *
 * Список providers профиля -- порядок показа: первый на странице, остальные
 * запас. Какой именно решён, едет в клиренс и в заголовок приложению.
 */

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

// Session -- то, что знает HTTP о клиенте на момент задания: nonce билета,
// адрес, язык.
type Session struct {
	Nonce    string
	ClientIP string
	Lang     string
}

// Challenge -- что показать. Widget -- готовый фрагмент для страницы (у
// внешних -- sitekey и скрипт, у картинки --
// data:URI). Data -- то же машинно, для /api.
type Challenge struct {
	Kind   string
	Data   map[string]any
	NeedJS bool
}

// Answer -- что прислал клиент: одно текстовое поле независимо от вида.
type Answer struct {
	Value string
	// Стороннему провайдеру нужен адрес клиента для remoteip.
	ClientIP string
}

type Provider interface {
	Kind() string
	// Issue выдаёт задание. Картинка кладёт состояние сама в roster под
	// nonce; внешним виджетам состояние не нужно.
	Issue(ctx context.Context, s Session) (Challenge, error)
	// Verify: nil -- принято; ErrWrong -- отказ; ErrUnavailable -- провайдер
	// не ответил, дальше решает on_error профиля.
	Verify(ctx context.Context, s Session, a Answer) error
}

// Deps -- то, что нужно провайдерам от процесса: roster под картинку,
// секреты под внешние виджеты. Secrets может быть nil.
type Deps struct {
	Roster  roster.Roster
	Secrets Secrets
}

// Chain -- основной и запасной провайдеры в порядке показа. primary --
// свой основной виджет правила страницы (пусто -- из профиля); запасной
// всегда из профиля, если он другого вида. Неизвестный вид -- ошибка
// программы: профиль такое отвергает при загрузке.
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

// ByKind -- провайдер цепочки по имени; nil, если такого нет.
func ByKind(chain []Provider, kind string) Provider {
	for _, p := range chain {
		if p.Kind() == kind {
			return p
		}
	}

	return nil
}
