/*
 * Токены капчи: клиренс (waf_clr) и билет виджета (waf_cap).
 *
 * Оба запечатанные, а не подписанные: в клиренсе лежат имя профиля, провайдер
 * и хеш отпечатка, в билете -- счёт клиента и номер попытки. Читать это
 * клиенту незачем, а подделать запечатанное нельзя ровно так же, как
 * подписанное: тег GCM -- тот же MAC.
 *
 * Ключ один на пару inspector-captcha / captcha-http и не делится ни с
 * челленджем, ни с auth: компрометация чужого скрипта не должна давать
 * выписать waf_clr. Форма и метка вывода ключа свои, чтобы токен auth с тем же
 * секретом здесь не открылся даже по ошибке.
 */

package token

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

const (
	clearancePrefix = "c1"
	ticketPrefix    = "k1"

	keyLabel  = "waf-captcha aead v1"
	minSecret = 16
)

var (
	ErrMalformed = errors.New("token is malformed")
	ErrSealed    = errors.New("token does not open with this key")
	ErrExpired   = errors.New("token has expired")
	ErrBind      = errors.New("token binding does not match")
)

/*
 * Clearance -- доказательство, что клиент прошёл виджет. Имена полей
 * короткие: токен едет в каждом запросе клиента.
 *
 * CID -- открытый идентификатор, который ставится отдельной короткой cookie
 * для локального слоя: по нему считают лимит и кладут в активный список.
 * Score -- счёт на момент выдачи; reverify_at сравнивается с текущим, а это
 * поле нужно аудиту: "решил картинку при 75".
 */
type Clearance struct {
	JTI      string   `json:"jti"`
	CID      string   `json:"cid"`
	Issued   int64    `json:"iat"`
	Expiry   int64    `json:"exp"`
	Profile  string   `json:"prf"`
	Provider string   `json:"prv"`
	Net      string   `json:"net,omitempty"`
	UA       string   `json:"ua,omitempty"`
	FP       string   `json:"fp,omitempty"`
	Flags    []string `json:"flg,omitempty"`
}

/*
 * Ticket -- задание виджета. Ставит инспектор вердиктом redirect (или deny
 * для SPA), читает HTTP. Attempt считает инспектор: каждый новый redirect
 * клиенту с билетом -- попытка плюс один. Номер живёт в аудите, а цену
 * провала назначают правила профиля (on: fail).
 */
type Ticket struct {
	Nonce   string `json:"n"`
	Return  string `json:"rd"`
	Profile string `json:"prf"`
	Attempt int    `json:"att"`
	Net     string `json:"net,omitempty"`
	UA      string `json:"ua,omitempty"`
	Expiry  int64  `json:"exp"`
}

// Bind -- к чему привязан токен. Пустое поле -- не проверяем.
type Bind struct {
	Net string
	UA  string
}

type Key struct {
	gcm cipher.AEAD
}

func NewKey(raw []byte) (*Key, error) {
	secret := strings.TrimSpace(string(raw))
	if len(secret) < minSecret {
		return nil, fmt.Errorf("key must be at least %d bytes, got %d",
			minSecret, len(secret))
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(keyLabel))

	block, err := aes.NewCipher(mac.Sum(nil))
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &Key{gcm: gcm}, nil
}

func (k *Key) seal(prefix string, payload any) (string, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, k.gcm.NonceSize(),
		k.gcm.NonceSize()+len(body)+k.gcm.Overhead())

	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	sealed := k.gcm.Seal(nonce, nonce, body, []byte(prefix))

	return prefix + "." + base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (k *Key) open(prefix, raw string, out any) error {
	kind, body, ok := strings.Cut(raw, ".")
	if !ok || kind != prefix || body == "" {
		return ErrMalformed
	}

	sealed, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return ErrMalformed
	}

	if len(sealed) < k.gcm.NonceSize()+k.gcm.Overhead() {
		return ErrMalformed
	}

	nonce := sealed[:k.gcm.NonceSize()]

	plain, err := k.gcm.Open(nil, nonce, sealed[k.gcm.NonceSize():], []byte(prefix))
	if err != nil {
		return ErrSealed
	}

	if err := json.Unmarshal(plain, out); err != nil {
		return ErrMalformed
	}

	return nil
}

func (k *Key) SealClearance(c *Clearance) (string, error) {
	return k.seal(clearancePrefix, c)
}

func (k *Key) SealTicket(t *Ticket) (string, error) {
	return k.seal(ticketPrefix, t)
}

/*
 * OpenClearance -- горячий путь инспектора. Любая ошибка значит одно: клиренса
 * нет; различаются они только кодом в аудите. Токен возвращается и при
 * ошибке срока и привязки -- аудиту нужен jti.
 */
func (k *Key) OpenClearance(raw string, now time.Time, want Bind) (*Clearance, error) {
	var c Clearance

	if err := k.open(clearancePrefix, raw, &c); err != nil {
		return nil, err
	}

	if c.JTI == "" || c.CID == "" || c.Expiry == 0 {
		return nil, ErrMalformed
	}

	if now.Unix() >= c.Expiry {
		return &c, ErrExpired
	}

	if want.Net != "" && c.Net != "" && want.Net != c.Net {
		return &c, ErrBind
	}

	if want.UA != "" && c.UA != "" && want.UA != c.UA {
		return &c, ErrBind
	}

	return &c, nil
}

// OpenTicket не проверяет привязку сам: инспектору она не нужна (он билет
// только перевыпускает), а HTTP сверяет её со своим представлением о клиенте.
func (k *Key) OpenTicket(raw string, now time.Time) (*Ticket, error) {
	var t Ticket

	if err := k.open(ticketPrefix, raw, &t); err != nil {
		return nil, err
	}

	if t.Nonce == "" || t.Expiry == 0 {
		return nil, ErrMalformed
	}

	if now.Unix() >= t.Expiry {
		return &t, ErrExpired
	}

	return &t, nil
}

// NewID -- 128 бит из crypto/rand: jti, cid и nonce задания.
func NewID() string {
	var b [16]byte

	if _, err := rand.Read(b[:]); err != nil {
		panic("captcha: crypto/rand is unavailable: " + err.Error())
	}

	return hex.EncodeToString(b[:])
}

// Subnet -- привязка к подсети, не к адресу: мобильные сети меняют адрес в
// течение сессии.
func Subnet(ip string, v4bits, v6bits int) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}

	addr = addr.Unmap()

	bits := v6bits
	if addr.Is4() {
		bits = v4bits
	}

	if bits <= 0 || bits > addr.BitLen() {
		bits = addr.BitLen()
	}

	prefix, err := addr.Prefix(bits)
	if err != nil {
		return ""
	}

	return prefix.String()
}

// Fingerprint -- короткий хеш User-Agent; полный UA в токене не нужен.
func Fingerprint(ua string) string {
	if ua == "" {
		return ""
	}

	sum := sha256.Sum256([]byte(ua))

	return hex.EncodeToString(sum[:4])
}
