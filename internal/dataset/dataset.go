/*
 * Запись в активный список сессий -- через keeper (docs/keeper.md).
 *
 * Список -- истина калитки: запись в нём означает, что сессию не завершили,
 * и инспектор сверяет с ним каждый запрос старше грейса своим зеркалом
 * (internal/livelist). Add при входе -- рождение записи, Remove при выходе --
 * её завершение; удаление записи из панели значит ровно то же самое.
 *
 * Событие -- запрос с ответом на waf.sets.<набор>.event: keeper пишет запись
 * в обменник, применяет в памяти, издаёт дельту и только потом отвечает. Когда
 * ответ пришёл, зеркала уже получают дельту -- этим и держится короткий
 * грейс. Отказ (full, store_unavailable) -- ошибка вызывающему, а не строка
 * в чужом логе.
 *
 * Сюда пишет только HTTP-процесс: рождение и завершение сессии -- события
 * входа и выхода, а инспектор списки только читает.
 */

package dataset

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
)

// Version -- версия кадра события.
const Version = 3

const (
	OpAdd    = "add"
	OpRemove = "remove"

	requestTimeout = 5 * time.Second
)

type Event struct {
	V     int    `json:"v"`
	Set   string `json:"set"`
	Op    string `json:"op"`
	Value string `json:"value,omitempty"`
	// Values -- пачка одной операции с общими сроком и поводом; keeper
	// принимает её целиком или никак (docs/keeper.md, «Пачка»).
	Values []string `json:"values,omitempty"`
	TTL    int      `json:"ttl,omitempty"`
	Origin string   `json:"origin"`
	Reason string   `json:"reason,omitempty"`
}

type Reply struct {
	OK    bool   `json:"ok"`
	Seq   uint64 `json:"seq,omitempty"`
	Epoch string `json:"epoch,omitempty"`
	Error string `json:"error,omitempty"`
	Limit int    `json:"limit,omitempty"`
}

// Rejected -- keeper принял запрос и отказал: потолок, чужой тип, обменник.
type Rejected struct {
	Code  string
	Limit int
}

func (r *Rejected) Error() string {
	if r.Limit > 0 {
		return fmt.Sprintf("list rejected: %s (limit %d)", r.Code, r.Limit)
	}

	return "list rejected: " + r.Code
}

// ErrUnreachable -- keeper не ответил: его нет или шина не доставила.
var ErrUnreachable = errors.New("keeper unreachable")

type Publisher struct {
	nc     *nats.Conn
	origin string
}

func New(nc *nats.Conn, origin string) *Publisher {
	if origin == "" {
		origin = "captcha"
	}

	return &Publisher{nc: nc, origin: origin}
}

/*
 * Add кладёт значение в набор на срок. TTL обязателен: keeper отвергает add
 * без него, и правильно делает -- запись без срока в списке живых сессий
 * пережила бы саму сессию. Набор адресуется именем: waf.sets.<имя>.
 */
func (p *Publisher) Add(name, value string, ttl time.Duration, reason string) error {
	if ttl <= 0 {
		return fmt.Errorf("dataset add without ttl")
	}

	return p.send(&Event{
		Op:     OpAdd,
		Set:    name,
		Value:  value,
		TTL:    int(ttl.Seconds()),
		Reason: reason,
	})
}

/*
 * AddMany кладёт пачку значений одним кадром: один запрос, один ответ, одно
 * окно секвенсора, одна дельта зеркалам -- и либо вся пачка, либо никак.
 * Так уезжает состав автономной системы при бане: сотни и тысячи
 * префиксов по одному значили бы ждать окно на каждом.
 */
func (p *Publisher) AddMany(name string, values []string, ttl time.Duration, reason string) error {
	if ttl <= 0 {
		return fmt.Errorf("dataset add without ttl")
	}

	if len(values) == 0 {
		return nil
	}

	if len(values) == 1 {
		return p.Add(name, values[0], ttl, reason)
	}

	return p.send(&Event{
		Op:     OpAdd,
		Set:    name,
		Values: values,
		TTL:    int(ttl.Seconds()),
		Reason: reason,
	})
}

/*
 * check -- у события есть набор и хоть одно значение: одиночное либо пачка.
 * Пачка едет без value, и прежняя проверка «value непустой» отвергала
 * каждую пачку ещё до keeper -- бан по анонсам и составу системы молча не
 * записывался, стоило префиксов оказаться больше одного.
 */
func (ev *Event) check() error {
	if ev.Set == "" || (ev.Value == "" && len(ev.Values) == 0) {
		return fmt.Errorf("dataset event needs set and value")
	}

	return nil
}

func (p *Publisher) Remove(name, value, reason string) error {
	return p.send(&Event{
		Op:     OpRemove,
		Set:    name,
		Value:  value,
		Reason: reason,
	})
}

func (p *Publisher) send(ev *Event) error {
	if p == nil || p.nc == nil {
		return nil
	}

	if err := ev.check(); err != nil {
		return err
	}

	ev.V = Version
	ev.Origin = p.origin

	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}

	msg, err := p.nc.Request("waf.sets."+ev.Set+".event", body, requestTimeout)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrUnreachable, err.Error())
	}

	var reply Reply
	if err := json.Unmarshal(msg.Data, &reply); err != nil {
		return fmt.Errorf("keeper reply is not json: %w", err)
	}

	if !reply.OK {
		return &Rejected{Code: reply.Error, Limit: reply.Limit}
	}

	return nil
}
