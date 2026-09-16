package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	envelopeVersion = 0x01
	nonceSize       = 12
	headerLen       = 1 + 2

	cacheTTL = 15 * time.Minute
)

func Open(blob []byte, key *rsa.PrivateKey) ([]byte, error) {
	if len(blob) < headerLen {
		return nil, fmt.Errorf("envelope: too short")
	}

	if blob[0] != envelopeVersion {
		return nil, fmt.Errorf("envelope: unsupported version %d", blob[0])
	}

	wrappedLen := int(binary.BigEndian.Uint16(blob[1:3]))

	if wrappedLen <= 0 || len(blob) < headerLen+wrappedLen+nonceSize {
		return nil, fmt.Errorf("envelope: truncated")
	}

	wrapped := blob[headerLen : headerLen+wrappedLen]
	nonce := blob[headerLen+wrappedLen : headerLen+wrappedLen+nonceSize]
	ciphertext := blob[headerLen+wrappedLen+nonceSize:]

	dek, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, wrapped, nil)
	if err != nil {
		return nil, fmt.Errorf("envelope: unwrap dek: %w", err)
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("envelope: dek: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("envelope: gcm: %w", err)
	}

	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("envelope: open: %w", err)
	}

	return plain, nil
}

func LoadKey(raw []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("contour key: not a pem block")
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("contour key: %w", err)
	}

	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("contour key: not an rsa key")
	}

	return key, nil
}

type entry struct {
	value string
	at    time.Time
}

type Store struct {
	base   string
	scope  string
	space  string
	key    *rsa.PrivateKey
	client *http.Client

	mu    sync.Mutex
	cache map[string]entry
}

func New(base, scope, keyFile string, timeout time.Duration) (*Store, error) {
	space := "default"

	if strings.HasPrefix(scope, "name:") {
		space = strings.TrimPrefix(scope, "name:")
		scope = ""
	}

	if base == "" || keyFile == "" {
		return nil, nil
	}

	raw, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("contour key: %w", err)
	}

	key, err := LoadKey(raw)
	if err != nil {
		return nil, err
	}

	return &Store{
		base:   strings.TrimRight(base, "/"),
		scope:  scope,
		space:  space,
		key:    key,
		client: &http.Client{Timeout: timeout},
		cache:  map[string]entry{},
	}, nil
}

func (s *Store) Get(ctx context.Context, id string) (string, error) {
	if s == nil {
		return "", fmt.Errorf("store secrets are not configured: " +
			"set WAF_CAPTCHA_CONTROLLER, WAF_CAPTCHA_SCOPE and WAF_CAPTCHA_CONTOUR_KEY")
	}

	if id == "" {
		return "", fmt.Errorf("empty store reference")
	}

	if v, ok := s.cached(id); ok {
		return v, nil
	}

	scope, err := s.resolveScope(ctx)
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("%s/api/%s/store/%s/blob", s.base, scope, id)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}

	res, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("store %s: %w", id, err)
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("store %s: controller answered %d", id, res.StatusCode)
	}

	blob, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("store %s: %w", id, err)
	}

	plain, err := Open(blob, s.key)
	if err != nil {
		return "", fmt.Errorf("store %s: %w", id, err)
	}

	value := strings.TrimRight(string(plain), "\r\n")

	s.remember(id, value)

	return value, nil
}

func (s *Store) resolveScope(ctx context.Context) (string, error) {
	s.mu.Lock()
	scope := s.scope
	s.mu.Unlock()

	if scope != "" {
		return scope, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.base+"/api/spaces", nil)
	if err != nil {
		return "", err
	}

	res, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("spaces: %w", err)
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("spaces: controller answered %d", res.StatusCode)
	}

	var body struct {
		Spaces []struct {
			UUID string `json:"uuid"`
			Name string `json:"name"`
		} `json:"spaces"`
	}

	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&body); err != nil {
		return "", fmt.Errorf("spaces: %w", err)
	}

	for _, sp := range body.Spaces {
		if sp.Name == s.space {
			s.mu.Lock()
			s.scope = sp.UUID
			s.mu.Unlock()

			return sp.UUID, nil
		}
	}

	return "", fmt.Errorf("spaces: no space named %q", s.space)
}

func (s *Store) cached(id string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.cache[id]
	if !ok || time.Since(e.at) > cacheTTL {
		return "", false
	}

	return e.value, true
}

func (s *Store) remember(id, value string) {
	s.mu.Lock()
	s.cache[id] = entry{value: value, at: time.Now()}
	s.mu.Unlock()
}
