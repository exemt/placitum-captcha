/*
 * Конфигурация процесса из переменных окружения. Одна на оба контейнера:
 * инспектор и HTTP собираются из одного образа и обязаны читать один профиль
 * и один ключ -- иначе клиренс, выписанный виджетом, не примет инспектор.
 *
 * Роль задаётся не переменной, а точкой входа: у инспектора обязателен subject,
 * у HTTP -- адрес прослушивания. Проверять то, чего в этой роли нет, значило бы
 * требовать от оператора заполнять чужие поля.
 */

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

	"github.com/exemt/placitum-shared/loglevel"
	"github.com/exemt/placitum-captcha/internal/token"
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
	// DataDir -- куда раскладывается поколение из KV. Каталог профилей
	// остаётся bootstrap: том с ним в контейнере только для чтения.
	DataDir string
	WebDir  string
	KeyFile string
	Key     *token.Key

	/*
	 * Два Redis, две роли. RedisURL -- обменник: заголовки запроса по
	 * локатору модуля, читает только инспектор. InternalURL -- внутренний
	 * Redis контура: корзины и роастер (нонсы, отказы, отзыв), общие у
	 * инспектора и HTTP-процесса. Источник адреса -- в InternalFrom:
	 * REDIS_INTERNAL_URL, путь inspector.conf с internal блока redis или REDIS_URL,
	 * когда адреса нет и состояние ложится в обменник.
	 */
	RedisURL     string
	InternalURL  string
	InternalFrom string
	StoreTimeout time.Duration
	/*
	 * GeoAddr -- gRPC-адрес кодера гео внутри контура (host:port): из него
	 * резолвятся анонсы, номер и состав системы -- для ключей корзин и для
	 * записей write: net | asn (docs/buckets.md). Пусто --
	 * корзины по системам молчат, а такие записи отвечают error. GeoTimeout
	 * -- сколько ждать кодер на промахе; ожидание синхронное и в бюджете
	 * сообщения.
	 */
	GeoAddr    string
	GeoTimeout time.Duration
	/*
	 * GeoNegMax -- потолок отрицательного кэша резолвера: сколько адресов, о
	 * которых кодер ничего не знает, помнить, чтобы не спрашивать о них
	 * снова. На потолке кэш не сбрасывается целиком, а вытесняется до девяти
	 * десятых -- иначе скан уникальными адресами возвращал бы кодеру всю
	 * нагрузку разом ровно в тот момент, когда её и так много. 0 -- умолчание
	 * резолвера.
	 */
	GeoNegMax int

	/*
	 * HTTPURL -- адрес captcha-http внутри контура. Нужен инспектору только
	 * в режиме gate.inline: страницу виджета он берёт у сервиса внутренним
	 * запросом и отдаёт модулю телом отказа. Пусто -- inline не работает, и
	 * профиль с ним отвечает редиректом, как обычный.
	 */
	HTTPURL string

	// Контроллер и ключ контура: ими открываются ссылки store: в профиле.
	// Пусто -- профиль обязан обходиться переменными окружения.
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
		Role:        role,
		Servers:     splitList(env("NATS_URL", "nats://127.0.0.1:4222")),
		Subject:     env("WAF_CAPTCHA_SUBJECT", "waf.req.captcha"),
		Name:        env("WAF_CAPTCHA_NAME", "captcha"),
		ProfilesDir: env("WAF_CAPTCHA_PROFILES", "./profiles"),
		DataDir:     env("WAF_CAPTCHA_DATA", ""),
		GeoAddr:     env("WAF_CAPTCHA_GEO_ADDR", ""),
		HTTPURL:     strings.TrimRight(env("WAF_CAPTCHA_HTTP_URL", ""), "/"),
		WebDir:      env("WAF_CAPTCHA_WEB", "./web"),
		KeyFile:     env("WAF_CAPTCHA_KEY_FILE", ""),
		Listen:      env("WAF_CAPTCHA_LISTEN", ":8080"),
		/*
		 * Secure по умолчанию: cookie сессии не должна уезжать по http нигде,
		 * кроме локального стенда без TLS. Выключается это осознанно, как и
		 * secure=off в waf_cookie_defaults стенда.
		 */
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
		/*
		 * 256, а не производная от числа воркеров: это число задаёт не только
		 * свою очередь, но и буфер подписки клиента NATS (queue_max + workers
		 * + 2), а буфер меряется темпом прихода на паузу, которую горутина
		 * доставки может пропустить, -- не тем, сколько воркеров за ней стоит.
		 * Прежние workers*8 давали 16 сообщений, это ~2 мс терпения на 10 000
		 * сообщений в секунду, и сообщения терялись молча на обычном дрожании.
		 */
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

	// Корзины и роастер: REDIS_INTERNAL_URL, затем internal блока redis в
	// inspector.conf, иначе обменник -- с предупреждением при старте.
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

	/*
	 * Таймаут обменника меньше бюджета волны нарочно: чтение заголовков -- часть
	 * дедлайна инспекции, и хранилище, отвечающее дольше, обязано превратиться
	 * в недоступный объект, а не съесть весь бюджет.
	 */
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

	/*
	 * Без обменника калитка не видит cookie: заголовки едут локатором, а не
	 * инлайном. Инспектор без REDIS_URL отвечал бы "сессии нет" на каждый
	 * запрос, то есть уводил бы на форму даже вошедших.
	 */
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

/*
 * Ключ подписи читается из файла и не генерируется на старте: две реплики
 * выписали бы взаимно непроверяемые токены, и вход ломался бы через раз, а
 * рестарт разлогинивал бы всех.
 */
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

/*
 * Стартовый порог журнала: словарь error_log nginx без emerg
 * (internal/loglevel). Поколение из KV переставляет порог живьём, переменная
 * действует до первого поколения с блоком settings.
 */
func parseLevel(s string) (slog.Level, error) {
	level, err := loglevel.Parse(s)
	if err != nil {
		return 0, fmt.Errorf("WAF_CAPTCHA_LOG: %w", err)
	}

	return level, nil
}
