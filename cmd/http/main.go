package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-captcha/internal/buckets"
	"github.com/exemt/placitum-captcha/internal/config"
	"github.com/exemt/placitum-captcha/internal/desired"
	"github.com/exemt/placitum-captcha/internal/livelist"
	"github.com/exemt/placitum-captcha/internal/provider"
	"github.com/exemt/placitum-captcha/internal/roster"
	"github.com/exemt/placitum-captcha/internal/secrets"
	"github.com/exemt/placitum-captcha/internal/stats"
	"github.com/exemt/placitum-shared/dataset"
	"github.com/exemt/placitum-shared/logkit"
	"github.com/exemt/placitum-shared/netinfo"
)

func main() {
	if err := run(); err != nil {
		slog.Error("startup failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(config.RoleHTTP)
	if err != nil {
		return err
	}

	var logs *logkit.Sink

	if config.LogShip() {
		logs = logkit.NewSink(config.LogWriter(cfg.Name), cfg.Name+"-http", nil)

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

	pages, err := loadPages(cfg.WebDir)
	if err != nil {
		return err
	}

	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	rev, err := openRoster(ctx, cfg, snap, log)
	if err != nil {
		return err
	}

	defer rev.Close()

	list, nc, closeBus, err := openBus(cfg, snap, log)
	if err != nil {
		return err
	}

	defer closeBus()

	if logs != nil && nc != nil {
		if err := logkit.Ensure(nc); err != nil {
			log.Warn("log stream", "error", err.Error())
		}

		logs.Attach(nc)
		log.Info("log stream", "stream", logkit.Stream,
			"subject", logkit.Subject(logs.Writer()))
	}

	sec, err := secrets.New(cfg.ControllerURL, cfg.Scope, cfg.ContourKeyFile, 10*time.Second)
	if err != nil {
		return err
	}

	var keeper provider.Secrets
	if sec != nil {
		keeper = sec

		log.Info("contour key loaded", "controller", cfg.ControllerURL, "scope", cfg.Scope)
	}

	config.LogInternalRedis(log, cfg.InternalURL, cfg.InternalFrom)
	bkt := buckets.New(nil, cfg.StoreTimeout)

	if cfg.InternalURL != "" {
		if dialed, err := buckets.Dial(cfg.InternalURL, cfg.StoreTimeout); err == nil {
			bkt = dialed
		} else {
			log.Warn("buckets on local ledger", "error", err.Error())
		}
	}

	resolver, err := netinfo.New(cfg.GeoAddr, cfg.GeoTimeout, cfg.GeoNegMax, log)
	if err != nil {
		log.Error("geo client", "addr", cfg.GeoAddr, "error", err.Error())
	}

	defer resolver.Close()

	var clearances *livelist.Mirror

	if nc != nil {
		var sets livelist.Blobs

		if cfg.InternalURL != "" {
			opened, err := livelist.OpenBlobs(cfg.InternalURL)
			if err != nil {
				return err
			}

			defer opened.Close()
			sets = opened
		}

		clearances = livelist.New(nc, sets, log)

		go watchClearanceLists(ctx, clearances, profiles)
	}

	srv := &server{
		cfg:        cfg,
		log:        log,
		profiles:   profiles,
		roster:     rev,
		pages:      pages,
		list:       list,
		clearances: clearances,
		secrets:    keeper,
		stats:      stats.New(),
		buckets:    bkt,
		resolver:   resolver,
	}

	go func() {
		tick := time.NewTicker(cfg.HeartbeatEvery * 15)
		defer tick.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				if pairs := srv.stats.Pairs(); len(pairs) > 0 {
					log.Info("stats", pairs...)
				}
			}
		}
	}()

	if nc != nil && cfg.DataDir != "" {
		desired.Bootstrap(profiles, cfg.DataDir, log)

		if _, err := desired.Watch(ctx, nc, profiles, cfg.DataDir, level, log); err != nil {
			log.Warn("desired watch failed", "error", err.Error())
		}
	}

	go profiles.Watch(ctx, cfg.ReloadEvery)
	go roster.Watch(ctx, rev, snap.Roster().RevokeRefresh.D(), func(err error) {
		log.Warn("revoke refresh failed", "error", err.Error())
	})

	http.Handle("/", srv)

	hs := &http.Server{
		Addr:              cfg.Listen,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Info("listening",
			"addr", cfg.Listen,
			"profiles", snap.Names(),
			"roster", snap.Roster().Store,
		)

		if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("listen failed", "error", err.Error())
			stop()
		}
	}()

	waitForSignal(profiles, log)
	stop()

	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return hs.Shutdown(shutdown)
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

func openBus(cfg *config.Config, snap *config.Snapshot, log *slog.Logger) (
	*dataset.Publisher, *nats.Conn, func(), error) {

	names := map[string]bool{}

	for _, p := range snap.All() {
		for _, r := range p.Rules {
			if r.List != "" {
				names[r.List] = true
			}
		}

		if p.Clearance.ListEnabled() {
			names[p.Clearance.List] = true
		}
	}

	if len(names) == 0 && cfg.DataDir == "" {
		return nil, nil, func() {}, nil
	}

	if len(cfg.Servers) == 0 {
		if len(names) > 0 {
			return nil, nil, nil,
				errors.New("NATS_URL is empty and a profile rule writes a list")
		}

		return nil, nil, func() {}, nil
	}

	nc, err := nats.Connect(joined(cfg.Servers),
		nats.Name("waf-captcha-http"),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(500*time.Millisecond),
	)
	if err != nil {
		return nil, nil, nil, err
	}

	for name := range names {
		log.Info("cleared list on", "set", name)
	}

	return dataset.New(nc, cfg.Name), nc, nc.Close, nil
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

func openRoster(ctx context.Context, cfg *config.Config, snap *config.Snapshot,
	log *slog.Logger) (roster.Roster, error) {

	rc := snap.Roster()

	if rc.Store == config.RosterMemory {
		log.Warn("roster is in-process: nonce, bans and revocation do not cross replicas")

		return roster.NewMemory(), nil
	}

	if cfg.InternalURL == "" {
		return nil, errors.New("REDIS_INTERNAL_URL is empty and roster.store is redis")
	}

	r, err := roster.NewRedis(cfg.InternalURL, rc.Prefix, cfg.StoreTimeout)
	if err != nil {
		return nil, err
	}

	if err := r.Ping(ctx); err != nil {
		return nil, err
	}

	return r, nil
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

		log.Info("shutting down", "signal", sig.String())

		return
	}
}
