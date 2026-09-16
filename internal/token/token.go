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

type Ticket struct {
	Nonce   string `json:"n"`
	Return  string `json:"rd"`
	Profile string `json:"prf"`
	Attempt int    `json:"att"`
	Net     string `json:"net,omitempty"`
	UA      string `json:"ua,omitempty"`
	Expiry  int64  `json:"exp"`
}

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

func NewID() string {
	var b [16]byte

	if _, err := rand.Read(b[:]); err != nil {
		panic("captcha: crypto/rand is unavailable: " + err.Error())
	}

	return hex.EncodeToString(b[:])
}

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

func Fingerprint(ua string) string {
	if ua == "" {
		return ""
	}

	sum := sha256.Sum256([]byte(ua))

	return hex.EncodeToString(sum[:4])
}
