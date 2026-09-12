/*
 * Точка входа инспектора капчи.
 *
 * Профили, ключ и обменник проверяются до подписки: калитка, которая
 * молча уводит всех на виджет из-за опечатки в каталоге, хуже не
 * запустившейся. Дальше профили перечитываются сами.
 */

package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-captcha/internal/audit"
	"github.com/exemt/placitum-captcha/internal/buckets"
	"github.com/exemt/placitum-captcha/internal/config"
	"github.com/exemt/placitum-captcha/internal/desired"
	"github.com/exemt/placitum-captcha/internal/livelist"
	"github.com/exemt/placitum-captcha/internal/queue"
	"github.com/exemt/placitum-captcha/internal/roster"
	"github.com/exemt/placitum-captcha/internal/stats"
	"github.com/exemt/placitum-captcha/internal/store"
	"github.com/exemt/placitum-shared/dataset"
	"github.com/exemt/placitum-shared/flow"
	"github.com/exemt/placitum-shared/logkit"
	"github.com/exemt/placitum-shared/netinfo"
	"github.com/exemt/placitum-shared/pulse"
)

func main() {
	if err := run(); err != nil {
		slog.Error("startup failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(config.RoleInspector)
	if err != nil {
		return err
	}

	/*
	 * Журнал процесса уезжает в waf.log той же пачкой, что и строки nginx:
	 * контур один, и искать причину отказа по трём десяткам docker-логов
	 * незачем. Приёмник поднимается раньше шины -- строки о том, как читался
	 * конфиг, копятся и уезжают первой же пачкой. Копия, не перенос: stdout
	 * остаётся на месте.
	 */
	var (
		logs  *logkit.Sink
		logIO *flow.Counter
	)

	if config.LogShip() {
		logIO = flow.New()
		logs = logkit.NewSink(config.LogWriter(cfg.Name), cfg.Name, logIO)

		defer logs.Close()
	}

	/*
	 * Порог журнала живой: поколение из KV переставляет его без рестарта
	 * (internal/loglevel). Переменная окружения задаёт стартовое значение.
	 */
	level := new(slog.LevelVar)
	level.Set(cfg.LogLevel)

	log := slog.New(slog.NewJSONHandler(logs.Tee(os.Stdout),
		&slog.HandlerOptions{Level: level}))
	slog.SetDefault(log)

	profiles, err := config.LoadProfiles(cfg.ProfilesDir, log)
	if err != nil {
		return err
	}

	snap := profiles.Current()
	log.Info("profiles loaded",
		"profiles", snap.Names(),
		"gen", snap.Gen,
		"fingerprint", snap.Fingerprint,
	)

	/*
	 * Обменник обязателен и проверяется на старте. Заголовки едут локатором, и
	 * инспектор без доступа к хранилищу не увидит ни одной cookie -- то есть
	 * уведёт на виджет даже тех, кто его уже прошёл.
	 */
	hot, err := store.NewRedis(cfg.RedisURL, cfg.StoreTimeout)
	if err != nil {
		return err
	}

	defer hot.Close()

	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	if err := hot.Ping(ctx); err != nil {
		return err
	}

	rev, err := openRoster(ctx, cfg, snap, log)
	if err != nil {
		return err
	}

	defer rev.Close()

	nc, err := nats.Connect(joined(cfg.Servers),
		nats.Name("waf-inspector-"+cfg.Name),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(500*time.Millisecond),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			log.Warn("bus disconnected", "error", errText(err))
		}),
		nats.ReconnectHandler(func(c *nats.Conn) {
			log.Info("bus reconnected", "server", c.ConnectedUrl())
		}),
	)
	if err != nil {
		return err
	}

	defer nc.Close()

	if err := audit.Ensure(nc); err != nil {
		log.Warn("audit stream", "error", err.Error())
	}

	/*
	 * Поток журнала заводит тот писатель, который пришёл первым: на контуре,
	 * где ни одна нода ещё не поднялась, им оказывается инспектор. Публикация
	 * в несуществующий поток -- тишина, а не ошибка.
	 */
	if logs != nil {
		if err := logkit.Ensure(nc); err != nil {
			log.Warn("log stream", "error", err.Error())
		}

		logs.Attach(nc)
		log.Info("log stream", "stream", logkit.Stream,
			"subject", logkit.Subject(logs.Writer()))
	}

	/*
	 * Поколение из KV. Bootstrap до подписки: рестарт, не успевший догнать
	 * watch, не должен откатываться на профили из образа и пускать людей по
	 * позавчерашнему набору факторов.
	 */
	var applied *desired.Applied

	if cfg.DataDir != "" {
		desired.Bootstrap(profiles, cfg.DataDir, log)

		applied, err = desired.Watch(ctx, nc, profiles, cfg.DataDir, level, log)
		if err != nil {
			log.Warn("desired watch failed", "error", err.Error())
		}
	}

	/*
	 * Корзины живут во внутреннем Redis контура, рядом с роастером и отдельно
	 * от обменника: один писатель на всех экземплярах -- и сумма одна на всех
	 * (docs/buckets.md).
	 */
	config.LogInternalRedis(log, cfg.InternalURL, cfg.InternalFrom)
	bkt, err := buckets.Dial(cfg.InternalURL, cfg.StoreTimeout)
	if err != nil {
		return err
	}

	resolver := openResolver(cfg, snap, log)

	defer resolver.Close()

	/*
	 * Зеркало активных списков клиренсов -- истина капчи. Пакеты и снапшоты
	 * оно читает из того же внутреннего Redis, что и корзины. Подписки
	 * сверяются со снимком профилей по шагу: список может появиться из KV
	 * после старта.
	 */
	sets, err := livelist.OpenBlobs(cfg.InternalURL)
	if err != nil {
		return err
	}

	defer sets.Close()

	clearances := livelist.New(nc, sets, log)

	go watchClearanceLists(ctx, clearances, profiles)

	/*
	 * События аудита уезжают пачками, а не по одной на инспекцию: при четырёх
	 * инспекторах в наборе это впятеро больше сообщений, чем запросов, и
	 * партия из одного сообщения кладёт вставку у потребителя.
	 *
	 * Закрывается после пула: в очереди события уже отвеченных запросов.
	 */
	auditSink := audit.NewSink(nc, log)

	h := &handler{cfg: cfg, log: log, nc: nc,
		audit: auditSink, profiles: profiles, store: hot, roster: rev,
		stats: stats.New(), buckets: bkt, resolver: resolver, clearances: clearances,
		lists: dataset.New(nc, cfg.Name)}

	if cfg.HTTPURL != "" {
		h.forms = newFormFetcher(cfg.HTTPURL)
	} else {
		log.Warn("WAF_CAPTCHA_HTTP_URL is empty: profiles with gate.inline answer " +
			"with a redirect")
	}
	pool := queue.New(cfg.Workers, cfg.QueueDepth, cfg.ReserveMS, cfg.MinBudgetMS,
		cfg.QueueFull, h.evaluate)
	h.pool = pool

	sub, err := nc.QueueSubscribe(cfg.Subject, cfg.Queue, h.receive)
	if err != nil {
		return err
	}

	// Забираем с шины сразу. pending — запас на полёт в колбэк, не очередь:
	// прокисшие выкидываем из pool, слот занимает свежий запрос.
	if err := sub.SetPendingLimits(cfg.QueueDepth+cfg.Workers+2, 4*1024*1024); err != nil {
		return err
	}

	log.Info("connected",
		"server", nc.ConnectedUrl(),
		"subject", cfg.Subject,
		"queue", cfg.Queue,
		"inspector", cfg.Name,
		"workers", cfg.Workers,
		"queue_max", cfg.QueueDepth,
		"queue_full", cfg.QueueFull,
		"conf", cfg.ConfPath,
		"roster", snap.Roster().Store,
	)

	go profiles.Watch(ctx, cfg.ReloadEvery)
	go roster.Watch(ctx, rev, snap.Roster().RevokeRefresh.D(), func(err error) {
		log.Warn("revoke refresh failed", "error", err.Error())
	})

	inspectorID := pulse.NewID()
	stopBeat := startHeartbeat(nc, cfg, inspectorID, pool, profiles, applied, h.stats, logIO, log)
	defer stopBeat()

	waitForSignal(profiles, log)
	stop()

	if err := sub.Drain(); err != nil {
		log.Warn("drain failed", "error", err.Error())
	}

	pool.Close()
	auditSink.Close()

	log.Info("drained",
		"accepted", pool.Accepted.Load(),
		"shed", pool.Shed.Load(),
		"expired", pool.Expired.Load(),
	)

	return nil
}

/*
 * openResolver поднимает резолвер сетей через кодер. ASN-корзины без него
 * молчат -- это предупреждение, а не отказ старта: контур может подниматься
 * по частям, а корзина адреса работает и так.
 */
/*
 * watchClearanceLists держит зеркало подписанным на списки клиренсов всех
 * профилей снимка. Ensure идемпотентен, сверка по шагу ничего не стоит.
 */
func watchClearanceLists(ctx context.Context, m *livelist.Mirror, profiles *config.Store) {
	defer m.Close()

	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()

	for {
		for _, p := range profiles.Current().All() {
			if p.Clearance.ListEnabled() {
				m.Ensure(p.Clearance.List)
			}
		}

		select {
		case <-ctx.Done():
			return

		case <-tick.C:
		}
	}
}

/*
 * openResolver -- клиент кодера гео. Нужен корзинам по системам и записям
 * write: net | asn; без адреса первые молчат, а вторые отвечают error, и об
 * этом стоит сказать при старте, а не узнать по журналу отказов.
 */
func openResolver(cfg *config.Config, snap *config.Snapshot, log *slog.Logger) *netinfo.Resolver {
	need := ""

	for _, p := range snap.All() {
		if p.Buckets.ASNNet.Enabled() || p.Buckets.ASNRouter.Enabled() {
			need = p.Name

			break
		}

		for _, r := range p.Rules {
			if r.List != "" && (r.Write == config.WriteNet || r.Write == config.WriteNetAll || r.Write == config.WriteASN) {
				need = p.Name

				break
			}
		}

		if need != "" {
			break
		}
	}

	if cfg.GeoAddr == "" {
		if need != "" {
			log.Warn("profile needs the geo coder but WAF_CAPTCHA_GEO_ADDR is empty: "+
				"asn buckets stay silent, write: net|asn answer error", "profile", need)
		}

		return nil
	}

	r, err := netinfo.New(cfg.GeoAddr, cfg.GeoTimeout, cfg.GeoNegMax, log)
	if err != nil {
		log.Error("geo client", "addr", cfg.GeoAddr, "error", err.Error())

		return nil
	}

	log.Info("geo resolver on", "addr", cfg.GeoAddr, "timeout", cfg.GeoTimeout.String())

	return r
}

/*
 * openRoster поднимает множество отзыва. В режиме memory отзыв живёт в
 * пределах процесса: для одной реплики и для тестов этого хватает, при
 * scale > 1 -- нет, и это свойство режима, а не недоделка.
 */
func openRoster(ctx context.Context, cfg *config.Config, snap *config.Snapshot,
	log *slog.Logger) (roster.Roster, error) {

	rc := snap.Roster()

	if rc.Store == config.RosterMemory {
		log.Warn("roster is in-process: revocation does not cross replicas")

		return roster.NewMemory(), nil
	}

	r, err := roster.NewRedis(cfg.InternalURL, rc.Prefix, cfg.StoreTimeout)
	if err != nil {
		return nil, err
	}

	if err := r.Ping(ctx); err != nil {
		return nil, err
	}

	n, err := r.Refresh(ctx)
	if err != nil {
		return nil, err
	}

	log.Info("roster ready", "prefix", rc.Prefix, "revoked", n)

	return r, nil
}

func startHeartbeat(
	nc *nats.Conn,
	cfg *config.Config,
	id string,
	pool *queue.Pool,
	profiles *config.Store,
	applied *desired.Applied,
	counters *stats.Counters,
	logIO *flow.Counter,
	log *slog.Logger,
) func() {
	subject := pulse.Subject(cfg.Name, id)
	log.Info("heartbeat on", "subject", subject, "id", id, "every", cfg.HeartbeatEvery.String())

	beat := func() {
		work := &pulse.Work{
			Workers:    cfg.Workers,
			QueueDepth: cfg.QueueDepth,
			Queued:     pool.Queued(),
			Accepted:   pool.Accepted.Load(),
			Shed:       pool.Shed.Load(),
			Expired:    pool.Expired.Load(),
		}
		io := map[string]flow.Flow{"inspect": pool.IO()}

		// Канал журнала -- там же, где темп инспекции: потерянная строка
		// видна ошибкой канала, и это единственное место, где её видно.
		// Сам приёмник о своих потерях молчит по построению.
		if logIO != nil {
			io["log"] = logIO.Snapshot()
		}
		msg := pulse.Build(id, cfg.Name, cfg.Subject, cfg.Queue, work, io)

		/*
		 * Кадр присутствия шире общего: у капчи в нём счётчики вердиктов и
		 * провайдеров. Общий кадр от этого не растёт -- Message встроен, и
		 * его поля ложатся в тот же объект JSON (placitum-shared/pulse).
		 */
		type frame struct {
			pulse.Message

			// Stats -- счётчики вердиктов и провайдеров с момента старта.
			Stats map[string]int64 `json:"stats,omitempty"`
		}

		if snap := profiles.Current(); snap != nil {
			msg.Rev = int(snap.Gen)
			msg.ConfigHash = snap.Fingerprint
			msg.Apply = desired.ApplyOK
			msg.Profiles = snap.Names()
		}

		/*
		 * Поколение контроллера перекрывает локальный отпечаток: сходимость
		 * флота считают по нему, и отпечаток каталога, который контроллер
		 * повторить не может, для этого не годится.
		 */
		if hash, rev, apply, names := applied.Snapshot(); apply != "" {
			msg.ConfigHash = hash
			msg.Rev = rev
			msg.Apply = apply

			if len(names) > 0 {
				msg.Profiles = names
			}
		}

		if err := pulse.PublishFrame(nc, subject,
			frame{Message: msg, Stats: counters.Snapshot()}); err != nil {
			log.Warn("heartbeat failed", "error", err.Error())
		}
	}

	beat()
	tick := time.NewTicker(cfg.HeartbeatEvery)

	done := make(chan struct{})

	go func() {
		for {
			select {
			case <-done:
				return
			case <-tick.C:
				beat()
			}
		}
	}()

	return func() {
		tick.Stop()
		close(done)
	}
}

func waitForSignal(profiles *config.Store, log *slog.Logger) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for {
		sig := <-ch

		if sig == syscall.SIGHUP {
			if _, err := profiles.Reload(); err != nil {
				log.Warn("sighup reload failed", "error", err.Error())
			}

			continue
		}

		log.Info("draining", "signal", sig.String())

		return
	}
}

func joined(servers []string) string {
	out := ""

	for i, s := range servers {
		if i > 0 {
			out += ","
		}

		out += s
	}

	return out
}

func errText(err error) string {
	if err == nil {
		return ""
	}

	return err.Error()
}
