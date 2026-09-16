package config

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/exemt/placitum-captcha/internal/token"
	"github.com/exemt/placitum-shared/loglevel"
)

const (
	RoleInspector = "inspector"
	RoleHTTP      = "http"
)

type Config struct {
	Role string

	Servers []string
	Subject string
	Name    string
	Queue   string

	ProfilesDir string
	DataDir     string
	WebDir      string
	KeyFile     string
	Key         *token.Key

	RedisURL     string
	InternalURL  string
	InternalFrom string
	StoreTimeout time.Duration
	GeoAddr      string
	GeoTimeout   time.Duration
	GeoNegMax    int

	HTTPURL string

	ControllerURL  string
	Scope          string
	ContourKeyFile string

	Listen       string
	CookieSecure bool
	RealIPHeader string

	ReloadEvery time.Duration

	Workers     int
	QueueDepth  int
	QueueFull   string
	QueueExpand string
	ConfPath    string
	ReserveMS   int
	MinBudgetMS int

	Versions []int
	LogLevel slog.Level

	HeartbeatEvery time.Duration
}

func Load(role string) (*Config, error) {
	c := &Config{
		Role:         role,
		Servers:      splitList(env("NATS_URL", "nats://127.0.0.1:4222")),
		Subject:      env("WAF_CAPTCHA_SUBJECT", "waf.req.captcha"),
		Name:         env("WAF_CAPTCHA_NAME", "captcha"),
		ProfilesDir:  env("WAF_CAPTCHA_PROFILES", "./profiles"),
		DataDir:      env("WAF_CAPTCHA_DATA", ""),
		GeoAddr:      env("WAF_CAPTCHA_GEO_ADDR", ""),
		HTTPURL:      strings.TrimRight(env("WAF_CAPTCHA_HTTP_URL", ""), "/"),
		WebDir:       env("WAF_CAPTCHA_WEB", "./web"),
		KeyFile:      env("WAF_CAPTCHA_KEY_FILE", ""),
		Listen:       env("WAF_CAPTCHA_LISTEN", ":8080"),
		CookieSecure: envBool("WAF_CAPTCHA_COOKIE_SECURE", true),
		RealIPHeader: env("WAF_CAPTCHA_REAL_IP_HEADER", "X-Forwarded-For"),

		ControllerURL:  env("WAF_CAPTCHA_CONTROLLER", ""),
		Scope:          env("WAF_CAPTCHA_SCOPE", ""),
		ContourKeyFile: env("WAF_CAPTCHA_CONTOUR_KEY", ""),
	}

	c.Queue = env("WAF_CAPTCHA_QUEUE", c.Name)

	var err error

	if c.Workers, err = envInt("WAF_CAPTCHA_WORKERS", runtime.GOMAXPROCS(0)); err != nil {
		return nil, err
	}

	q := queueSettings{
		Max:    256,
		Full:   QueueFullDrop,
		Expand: QueueExpandOff,
	}

	var file queueFile

	c.ConfPath = confPath("WAF_CAPTCHA_CONF")
	if c.ConfPath != "" {
		var ferr error
		if file, ferr = loadQueueFile(c.ConfPath); ferr != nil {
			return nil, ferr
		}

		applyQueueFile(&q, file)
	}

	c.RedisURL = exchangeRedis(file)
	c.InternalURL, c.InternalFrom = internalRedis(c.ConfPath, file, c.RedisURL)

	if q.Max, err = envIntIfSet("WAF_CAPTCHA_QUEUE_DEPTH", q.Max); err != nil {
		return nil, err
	}

	c.QueueDepth = q.Max
	c.QueueFull = envOverride("WAF_CAPTCHA_QUEUE_FULL", q.Full)
	c.QueueExpand = envOverride("WAF_CAPTCHA_QUEUE_EXPAND", q.Expand)

	if c.ReserveMS, err = envInt("WAF_CAPTCHA_RESERVE_MS", 1); err != nil {
		return nil, err
	}

	if c.MinBudgetMS, err = envInt("WAF_CAPTCHA_MIN_BUDGET_MS", 1); err != nil {
		return nil, err
	}

	if c.Versions, err = envIntList("WAF_CAPTCHA_VERSIONS", []int{2}); err != nil {
		return nil, err
	}

	if c.LogLevel, err = parseLevel(env("WAF_CAPTCHA_LOG", "info")); err != nil {
		return nil, err
	}

	if c.HeartbeatEvery, err = envDuration("WAF_HEARTBEAT_EVERY", 4*time.Second); err != nil {
		return nil, err
	}

	if c.ReloadEvery, err = envDuration("WAF_CAPTCHA_RELOAD_EVERY", time.Second); err != nil {
		return nil, err
	}

	if c.GeoTimeout, err = envDuration("WAF_CAPTCHA_GEO_TIMEOUT", 500*time.Millisecond); err != nil {
		return nil, err
	}

	if c.GeoNegMax, err = envInt("WAF_CAPTCHA_GEO_NEG_MAX", 0); err != nil {
		return nil, err
	}

	if c.StoreTimeout, err = envDuration("WAF_CAPTCHA_STORE_TIMEOUT", 150*time.Millisecond); err != nil {
		return nil, err
	}

	return c, c.validate()
}

func (c *Config) validate() error {
	if c.Name == "" {
		return fmt.Errorf("WAF_CAPTCHA_NAME is empty")
	}

	if err := c.loadKey(); err != nil {
		return err
	}

	abs, err := filepath.Abs(c.ProfilesDir)
	if err != nil {
		return fmt.Errorf("WAF_CAPTCHA_PROFILES: %w", err)
	}

	st, err := os.Stat(abs)
	if err != nil {
		return fmt.Errorf("WAF_CAPTCHA_PROFILES: %w", err)
	}

	if !st.IsDir() {
		return fmt.Errorf("WAF_CAPTCHA_PROFILES: %s is not a directory", abs)
	}

	c.ProfilesDir = abs

	switch c.Role {
	case RoleInspector:
		return c.validateInspector()

	case RoleHTTP:
		return c.validateHTTP()
	}

	return fmt.Errorf("unknown role %q", c.Role)
}

func (c *Config) validateInspector() error {
	if len(c.Servers) == 0 {
		return fmt.Errorf("NATS_URL is empty")
	}

	if c.Subject == "" || c.Queue == "" {
		return fmt.Errorf("subject and queue must not be empty")
	}

	if c.Workers < 1 {
		return fmt.Errorf("WAF_CAPTCHA_WORKERS must be positive, got %d", c.Workers)
	}

	if c.QueueDepth < 1 {
		return fmt.Errorf("queue_max must be positive, got %d", c.QueueDepth)
	}

	switch c.QueueFull {
	case QueueFullDrop, QueueFullWait:
	default:
		return fmt.Errorf("queue_full must be drop or wait, got %q", c.QueueFull)
	}

	switch c.QueueExpand {
	case QueueExpandOff, QueueExpandAsk:
	default:
		return fmt.Errorf("queue_expand must be off or ask, got %q", c.QueueExpand)
	}

	if c.ReserveMS < 0 || c.MinBudgetMS < 0 {
		return fmt.Errorf("WAF_CAPTCHA_RESERVE_MS and WAF_CAPTCHA_MIN_BUDGET_MS must not be negative")
	}

	if len(c.Versions) == 0 {
		return fmt.Errorf("WAF_CAPTCHA_VERSIONS is empty")
	}

	if c.RedisURL == "" {
		return fmt.Errorf("REDIS_URL is empty: the inspector reads the clearance cookie " +
			"from the module store, and headers never travel inline")
	}

	return nil
}

func (c *Config) validateHTTP() error {
	if c.Listen == "" {
		return fmt.Errorf("WAF_CAPTCHA_LISTEN is empty")
	}

	abs, err := filepath.Abs(c.WebDir)
	if err != nil {
		return fmt.Errorf("WAF_CAPTCHA_WEB: %w", err)
	}

	st, err := os.Stat(abs)
	if err != nil {
		return fmt.Errorf("WAF_CAPTCHA_WEB: %w", err)
	}

	if !st.IsDir() {
		return fmt.Errorf("WAF_CAPTCHA_WEB: %s is not a directory", abs)
	}

	c.WebDir = abs

	return nil
}

func (c *Config) loadKey() error {
	if c.KeyFile == "" {
		return fmt.Errorf("WAF_CAPTCHA_KEY_FILE is empty: the key is shared by " +
			"the inspector and the widget service and cannot be generated per process")
	}

	raw, err := os.ReadFile(c.KeyFile)
	if err != nil {
		return fmt.Errorf("WAF_CAPTCHA_KEY_FILE: %w", err)
	}

	key, err := token.NewKey(raw)
	if err != nil {
		return fmt.Errorf("WAF_CAPTCHA_KEY_FILE: %w", err)
	}

	c.Key = key

	return nil
}

func (c *Config) Supports(v int) bool {
	for _, known := range c.Versions {
		if known == v {
			return true
		}
	}

	return false
}

func env(name, def string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}

	return def
}

func envBool(name string, def bool) bool {
	raw, ok := os.LookupEnv(name)
	if !ok || raw == "" {
		return def
	}

	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "on", "true", "yes":
		return true
	case "0", "off", "false", "no":
		return false
	}

	return def
}

func envInt(name string, def int) (int, error) {
	return envIntIfSet(name, def)
}

func envIntIfSet(name string, def int) (int, error) {
	raw, ok := os.LookupEnv(name)
	if !ok || raw == "" {
		return def, nil
	}

	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}

	return v, nil
}

func envIntList(name string, def []int) ([]int, error) {
	raw, ok := os.LookupEnv(name)
	if !ok || raw == "" {
		return def, nil
	}

	var out []int

	for _, part := range splitList(raw) {
		v, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}

		out = append(out, v)
	}

	return out, nil
}

func envDuration(name string, def time.Duration) (time.Duration, error) {
	raw, ok := os.LookupEnv(name)
	if !ok || raw == "" {
		return def, nil
	}

	d, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}

	if d <= 0 {
		return 0, fmt.Errorf("%s must be positive", name)
	}

	return d, nil
}

func splitList(s string) []string {
	var out []string

	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}

	return out
}

func parseLevel(s string) (slog.Level, error) {
	level, err := loglevel.Parse(s)
	if err != nil {
		return 0, fmt.Errorf("WAF_CAPTCHA_LOG: %w", err)
	}

	return level, nil
}
