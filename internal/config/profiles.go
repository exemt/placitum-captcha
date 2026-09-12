/*
 * Каталог профилей и его горячая перезагрузка.
 *
 * Снимок неизменяем и подменяется целиком: правка одного профиля не должна
 * оставлять контур в состоянии "половина старого, половина нового". Ошибка
 * разбора любого профиля отвергает всё поколение -- действующий набор при этом
 * не трогают, как у modsec с его apply_failed.
 *
 * Отпечаток -- имя, размер и mtime файлов. Читать содержимое раз в секунду
 * ради сравнения незачем: правят профиль руками, а не гонкой записей.
 */

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

// Limits -- общая на процесс секция лимитов HTTP. Как и roster, объявляется
// в профиле, но расходиться между профилями не может.
func (s *Snapshot) Limits() Limits {
	if s == nil {
		return Limits{}
	}

	return s.limits
}

// Roster -- общая на процесс секция отзыва. Профили обязаны объявлять её
// одинаково, это проверяется при загрузке.
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

/*
 * ByPath нужен HTTP-процессу: к нему приходят по адресу страницы, а не по
 * маршруту приложения, и route.profile там взяться неоткуда. Билет waf_cap
 * имя профиля несёт, но его может не быть -- открыли страницу закладкой.
 */
func (s *Snapshot) ByPath(uri string) (*Profile, bool) {
	if s == nil {
		return nil, false
	}

	p, ok := s.byPath[uri]

	return p, ok
}

// All -- профили в лексическом порядке имён.
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

// Dir -- каталог, по которому сейчас читают. Нужен раскатке: она кладёт новое
// поколение рядом и переключает сюда.
func (s *Store) Dir() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.dir
}

/*
 * ReloadFrom переключает каталог и читает его целиком. Провал не трогает
 * действующий снимок и не меняет каталог: поколение, которое не разобралось,
 * не должно оставлять контур ни с половиной профилей, ни без них.
 */
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

// Reload перечитывает каталог, если изменился отпечаток. Первое значение --
// была ли подмена.
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
				// Битое поколение не подменяет действующее: калитка
				// продолжает работать по последнему исправному набору.
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

		// Мёртвые поля: одно поколение читаются и игнорируются с
		// предупреждением, потом станут ошибкой.
		p.Deprecated = p.deprecations()

		for _, warn := range p.Deprecated {
			if s.log != nil {
				s.log.Warn("profile carries a dead field", "profile", name, "field", warn)
			}
		}

		snap.byName[name] = p
		snap.names = append(snap.names, name)

		/*
		 * Один адрес страницы у нескольких профилей -- норма, не ошибка:
		 * профили различаются политикой, а страница у них общая. HTTP
		 * находит профиль по билету, а по адресу -- только когда билета нет,
		 * и тогда годится любой с этим адресом: показать он сможет лишь
		 * "билета нет, вернитесь на сайт".
		 */
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

	/*
	 * Проба зовёт инспектор профилем _probe и ждёт redirect. Профиль
	 * зарезервирован: если оператор его не положил, он выводится из default
	 * с when: always -- чтобы healthcheck не зависел от порога.
	 */
	if _, ok := snap.byName[ProbeName]; !ok {
		probe := def.probeVariant()
		snap.byName[ProbeName] = probe
		snap.names = append(snap.names, ProbeName)
	}

	/*
	 * Roster -- свойство процесса, а не профиля: множество отзыва читается
	 * одно на всех, и два префикса означали бы два множества у одного
	 * инспектора. Секция остаётся в профиле, потому что там её ищут, но
	 * расхождение обязано быть ошибкой, а не молча выигравшим default.
	 */
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

/*
 * attachPage читает свою страницу капчи, если она приехала с поколением.
 * Нет файла -- профиль работает по встроенной; есть, но не разбирается --
 * ошибка снапшота, как и битый profile.yaml.
 */
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
