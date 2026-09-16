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

	var (
		logs  *logkit.Sink
		logIO *flow.Counter
	)

	if config.LogShip() {
		logIO = flow.New()
		logs = logkit.NewSink(config.LogWriter(cfg.Name), cfg.Name, logIO)

		defer logs.Close()
	}

	level := new(slog.LevelVar)
	level.Set(cfg.LogLevel)

	log := slog.New(slog.NewJSONHandler(logs.Tee(os.Stdout),
		&slog.HandlerOptions{Level: level}))

	log.Info("build", "version", version, "revision", revision)
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

	if logs != nil {
		if err := logkit.Ensure(nc); err != nil {
			log.Warn("log stream", "error", err.Error())
		}

		logs.Attach(nc)
		log.Info("log stream", "stream", logkit.Stream,
			"subject", logkit.Subject(logs.Writer()))
	}

	var applied *desired.Applied

	if cfg.DataDir != "" {
		desired.Bootstrap(profiles, cfg.DataDir, log)

		applied, err = desired.Watch(ctx, nc, profiles, cfg.DataDir, level, log)
		if err != nil {
			log.Warn("desired watch failed", "error", err.Error())
		}
	}

	config.LogInternalRedis(log, cfg.InternalURL, cfg.InternalFrom)
	bkt, err := buckets.Dial(cfg.InternalURL, cfg.StoreTimeout)
	if err != nil {
		return err
	}

	resolver := openResolver(cfg, snap, log)

	defer resolver.Close()

	sets, err := livelist.OpenBlobs(cfg.InternalURL)
	if err != nil {
		return err
	}

	defer sets.Close()

	clearances := livelist.New(nc, sets, log)

	go watchClearanceLists(ctx, clearances, profiles)

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

		if logIO != nil {
			io["log"] = logIO.Snapshot()
		}
		msg := pulse.Build(id, cfg.Name, cfg.Subject, cfg.Queue, work, io)
		msg.Version, msg.Revision = version, revision

		type frame struct {
			pulse.Message

			Stats map[string]int64 `json:"stats,omitempty"`
		}

		if snap := profiles.Current(); snap != nil {
			msg.Rev = int(snap.Gen)
			msg.ConfigHash = snap.Fingerprint
			msg.Apply = desired.ApplyOK
			msg.Profiles = snap.Names()
		}

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
