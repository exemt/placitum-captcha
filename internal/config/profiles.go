package config

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	profileFile = "profile.yaml"
	pageFile    = "captcha.html"
)

type Snapshot struct {
	Gen         int64
	Fingerprint string

	byName map[string]*Profile
	byPath map[string]*Profile
	names  []string
	roster Roster
	limits Limits
}

func (s *Snapshot) Limits() Limits {
	if s == nil {
		return Limits{}
	}

	return s.limits
}

func (s *Snapshot) Roster() Roster {
	if s == nil {
		return Roster{}
	}

	return s.roster
}

func (s *Snapshot) Profile(name string) (*Profile, bool) {
	if s == nil {
		return nil, false
	}

	if name == "" {
		name = DefaultName
	}

	p, ok := s.byName[name]

	return p, ok
}

func (s *Snapshot) ByPath(uri string) (*Profile, bool) {
	if s == nil {
		return nil, false
	}

	p, ok := s.byPath[uri]

	return p, ok
}

func (s *Snapshot) All() []*Profile {
	if s == nil {
		return nil
	}

	out := make([]*Profile, 0, len(s.names))

	for _, name := range s.names {
		out = append(out, s.byName[name])
	}

	return out
}

func (s *Snapshot) Names() []string {
	if s == nil {
		return nil
	}

	return s.names
}

type Store struct {
	mu  sync.Mutex
	dir string
	log *slog.Logger
	cur atomic.Pointer[Snapshot]
	gen atomic.Int64
}

func LoadProfiles(dir string, log *slog.Logger) (*Store, error) {
	s := &Store{dir: dir, log: log}

	snap, err := s.read()
	if err != nil {
		return nil, err
	}

	s.cur.Store(snap)

	return s, nil
}

func (s *Store) Current() *Snapshot { return s.cur.Load() }

func (s *Store) Dir() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.dir
}

func (s *Store) ReloadFrom(dir string) error {
	s.mu.Lock()
	prev := s.dir
	s.dir = dir
	s.mu.Unlock()

	snap, err := s.read()
	if err != nil {
		s.mu.Lock()
		s.dir = prev
		s.mu.Unlock()

		return err
	}

	s.cur.Store(snap)

	return nil
}

func (s *Store) Reload() (bool, error) {
	fp, err := fingerprint(s.Dir())
	if err != nil {
		return false, err
	}

	if cur := s.cur.Load(); cur != nil && cur.Fingerprint == fp {
		return false, nil
	}

	snap, err := s.read()
	if err != nil {
		return false, err
	}

	s.cur.Store(snap)

	return true, nil
}

func (s *Store) Watch(ctx context.Context, every time.Duration) {
	if every <= 0 {
		return
	}

	tick := time.NewTicker(every)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-tick.C:
			changed, err := s.Reload()
			if err != nil {
				s.log.Error("profiles reload failed", "error", err.Error())
				continue
			}

			if changed {
				snap := s.Current()
				s.log.Info("profiles reloaded",
					"gen", snap.Gen,
					"profiles", snap.Names(),
					"fingerprint", snap.Fingerprint,
				)
			}
		}
	}
}

func (s *Store) read() (*Snapshot, error) {
	dir := s.Dir()

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("profiles: %w", err)
	}

	snap := &Snapshot{
		byName: map[string]*Profile{},
		byPath: map[string]*Profile{},
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}

		name := e.Name()
		path := filepath.Join(dir, name, profileFile)

		raw, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}

			return nil, fmt.Errorf("profiles: %w", err)
		}

		p, err := ParseProfile(name, raw)
		if err != nil {
			return nil, err
		}

		if err := attachPage(p, filepath.Join(dir, name)); err != nil {
			return nil, err
		}

		if err := p.Validate(); err != nil {
			return nil, fmt.Errorf("profile %s: %w", name, err)
		}

		snap.byName[name] = p
		snap.names = append(snap.names, name)

		if p.Path != "" {
			if _, dup := snap.byPath[p.Path]; !dup {
				snap.byPath[p.Path] = p
			}
		}
	}

	def, ok := snap.byName[DefaultName]
	if !ok {
		return nil, fmt.Errorf("profiles: %s is missing in %s", DefaultName, dir)
	}

	if _, ok := snap.byName[ProbeName]; !ok {
		probe := def.probeVariant()
		snap.byName[ProbeName] = probe
		snap.names = append(snap.names, ProbeName)
	}

	for _, name := range snap.names {
		if snap.byName[name].Roster != def.Roster {
			return nil, fmt.Errorf("profile %s: roster differs from %s; "+
				"the revoke set is shared by the whole process", name, DefaultName)
		}
	}

	for _, name := range snap.names {
		if snap.byName[name].Limits != def.Limits {
			return nil, fmt.Errorf("profile %s: limits differ from %s; "+
				"HTTP counters are shared by the whole process", name, DefaultName)
		}
	}

	snap.roster = def.Roster
	snap.limits = def.Limits

	sort.Strings(snap.names)

	fp, err := fingerprint(dir)
	if err != nil {
		return nil, err
	}

	snap.Fingerprint = fp
	snap.Gen = s.gen.Add(1)

	return snap, nil
}

func attachPage(p *Profile, dir string) error {
	raw, err := os.ReadFile(filepath.Join(dir, pageFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}

		return fmt.Errorf("profile %s: %w", p.Name, err)
	}

	t, err := template.New(pageFile).Parse(string(raw))
	if err != nil {
		return fmt.Errorf("profile %s: %s: %w", p.Name, pageFile, err)
	}

	p.Page = t

	return nil
}

func fingerprint(dir string) (string, error) {
	h := sha256.New()

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}

		h.Write([]byte(filepath.ToSlash(rel)))
		h.Write([]byte{0})
		h.Write([]byte(strconv.FormatInt(info.Size(), 10)))
		h.Write([]byte{0})
		h.Write([]byte(strconv.FormatInt(info.ModTime().UnixNano(), 10)))
		h.Write([]byte{0})

		return nil
	})
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)[:8]), nil
}
