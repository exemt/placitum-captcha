/*
 * Чтение объекта обменника по локатору. Калитке нужен ровно один объект --
 * заголовки: cookie сессии едет там, а не инлайном в сообщении.
 *
 * Это единственное обращение инспектора наружу на горячем пути, и оно жёстко
 * ограничено по времени: чтение входит в бюджет волны, и обменник, отвечающий
 * дольше, обязан превратиться в недоступный объект, а не съесть дедлайн.
 *
 * Недоступный объект не решает за модуль. Для калитки он означает "сессии не
 * видно", а что с этим делать -- решает лестница вердикта, ровно как при
 * отсутствии cookie.
 */

package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/exemt/placitum-captcha/internal/protocol"
)

// Причины недоступности. Формат совпадает с тем, что присылает модуль, чтобы в
// аудите они читались одинаково.
const (
	UnavailableNoStore  = "store_unconfigured"
	UnavailableError    = "store_error"
	UnavailableDriver   = "unknown_driver"
	UnavailableNotFound = "store_miss"
)

/*
 * Недоступность бывает двух родов, и путать их нельзя.
 *
 * Её обнаружил модуль (причина приехала в локаторе) -- маршрут ею уже
 * распорядился классом body у waf_exception, и раз сообщение всё-таки дошло,
 * решение было "продолжать": для калитки это то же, что "cookie нет", и решает
 * лестница вердикта.
 *
 * Её обнаружили мы (обменник не ответил, ключа нет, объект не разобрался) --
 * о ней модуль не знает: он положил объект и считает его на месте. Cookie
 * лежал, и то, что мы его не прочли, о клиенте не говорит ничего -- это наш
 * сбой, и признаётся он вердиктом error.
 *
 * Строкой эти два рода не различить: часть причин модуль называет теми же
 * словами. Поэтому признак fault едет отдельно от причины.
 */

var ErrUnknownDriver = errors.New("unknown store driver")

type Redis struct {
	client  *redis.Client
	timeout time.Duration
}

func NewRedis(url string, timeout time.Duration) (*Redis, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}

	opt.ReadTimeout = timeout
	opt.WriteTimeout = timeout
	opt.DialTimeout = timeout

	return &Redis{client: redis.NewClient(opt), timeout: timeout}, nil
}

func (s *Redis) Get(ctx context.Context, driver, key string) ([]byte, error) {
	if driver != "redis" {
		return nil, ErrUnknownDriver
	}

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	return s.client.Get(ctx, key).Bytes()
}

/*
 * Put кладёт объект под ключ запроса: страницу виджета для deny телом ответа
 * (секция rewrite). Ключ строит вызывающий по правилу модуля
 * <node>:<rid>:req:<суффикс>; TTL короткий -- модуль читает объект сразу, а
 * непрочитанный (запрос умер раньше) не должен жить в обменнике.
 */
func (s *Redis) Put(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	return s.client.Set(ctx, key, value, ttl).Err()
}

func (s *Redis) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

	return s.client.Ping(ctx).Err()
}

func (s *Redis) Close() error { return s.client.Close() }

/*
 * Headers достаёт объект заголовков. Лежит он JSON-массивом пар: порядок
 * получения значим, а дубликаты имён в объекте потерялись бы.
 *
 * Второе значение -- причина, по которой заголовков нет. Пустая строка при
 * пустом срезе означает "маршрут их не снимает" -- тоже штатный исход, но
 * разбирается он оператором иначе, чем отказ обменника.
 */
func Headers(ctx context.Context, s *Redis, loc *protocol.Locator) (
	[]protocol.Header, string, bool) {

	switch {
	case loc == nil:
		return nil, "", false

	case loc.Unavailable != "":
		return nil, loc.Unavailable, false

	case loc.Driver == "":
		return nil, "", false
	}

	if s == nil {
		return nil, UnavailableNoStore, true
	}

	raw, err := s.Get(ctx, loc.Driver, loc.Key)

	switch {
	case errors.Is(err, redis.Nil):
		return nil, UnavailableNotFound, true

	case errors.Is(err, ErrUnknownDriver):
		return nil, UnavailableDriver, true

	case err != nil:
		return nil, UnavailableError, true
	}

	var pairs []protocol.Header
	if err := json.Unmarshal(raw, &pairs); err != nil {
		return nil, UnavailableError, true
	}

	return pairs, "", false
}

/*
 * Pair достаёт заголовки и строку запроса одним походом. Строка нужна только
 * затем, чтобы вернуть клиента ровно туда, откуда его увели: в сообщении едет
 * лишь путь, а query лежит отдельным объектом обменника.
 *
 * MGET, а не два GET: у объектов одного запроса один обменник, и второй
 * round-trip здесь -- это второй round-trip внутри бюджета волны.
 */
func Pair(ctx context.Context, s *Redis, hdr, args *protocol.Locator) (
	[]protocol.Header, string, string, bool) {

	if s == nil || hdr == nil || args == nil ||
		hdr.Driver != "redis" || args.Driver != "redis" ||
		hdr.Unavailable != "" || args.Unavailable != "" {
		// Смешанные формы разбираются поодиночке: случай редкий, и
		// специальный путь для него стоил бы дороже лишнего похода.
		pairs, why, fault := Headers(ctx, s, hdr)

		return pairs, argsOf(ctx, s, args), why, fault
	}

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	vals, err := s.client.MGet(ctx, hdr.Key, args.Key).Result()
	if err != nil || len(vals) != 2 {
		return nil, "", UnavailableError, true
	}

	raw, ok := vals[0].(string)
	if !ok {
		return nil, str(vals[1]), UnavailableNotFound, true
	}

	var pairs []protocol.Header
	if err := json.Unmarshal([]byte(raw), &pairs); err != nil {
		return nil, str(vals[1]), UnavailableError, true
	}

	return pairs, str(vals[1]), "", false
}

func argsOf(ctx context.Context, s *Redis, loc *protocol.Locator) string {
	if s == nil || loc == nil || loc.Driver == "" || loc.Unavailable != "" {
		return ""
	}

	raw, err := s.Get(ctx, loc.Driver, loc.Key)
	if err != nil {
		return ""
	}

	return string(raw)
}

func str(v any) string {
	s, _ := v.(string)

	return s
}

// Value -- первое значение заголовка без учёта регистра имени.
func Value(pairs []protocol.Header, name string) string {
	for _, h := range pairs {
		if strings.EqualFold(h.Name(), name) {
			return h.Value()
		}
	}

	return ""
}

/*
 * Cookie ищет значение по всем заголовкам Cookie сразу: HTTP/2 разрешает
 * разбивать их на несколько полей, и браузеры этим пользуются. Разбор
 * намеренно снисходительный -- чужие cookie в той же строке нас не касаются,
 * и ронять из-за них разбор своей значило бы отдать выход из системы любому,
 * кто поставит клиенту битую cookie.
 */
func Cookie(pairs []protocol.Header, name string) string {
	for _, h := range pairs {
		if !strings.EqualFold(h.Name(), "cookie") {
			continue
		}

		if v := cookieFrom(h.Value(), name); v != "" {
			return v
		}
	}

	return ""
}

func cookieFrom(line, name string) string {
	for len(line) > 0 {
		var part string

		if i := strings.IndexByte(line, ';'); i >= 0 {
			part, line = line[:i], line[i+1:]
		} else {
			part, line = line, ""
		}

		part = strings.TrimSpace(part)

		key, value, ok := strings.Cut(part, "=")
		if !ok || strings.TrimSpace(key) != name {
			continue
		}

		return strings.Trim(strings.TrimSpace(value), `"`)
	}

	return ""
}
