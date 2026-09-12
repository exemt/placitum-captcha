/*
 * Наш словарь действий против схемы провода.
 *
 * В заголовке protocol.go источником истины назван
 * docs/messages/inspector.schema.json -- этот тест и есть то место, где
 * обещание проверяется. Расходятся такие копии не в момент правки, а через два
 * месяца после неё: словарь расширят в модуле и в схеме, а здесь забудут, и
 * правило с новой осью перестанет грузиться без единой ошибки.
 *
 * Схема лежит в дереве репозитория, а не в модуле Go. Прогон из распакованного
 * контейнера, где смонтирован только inspectors/captcha, её не увидит -- тогда
 * тест честно пропускается: проверять нечего, а падать из-за отсутствия
 * контракта значило бы ломать сборку там, где она и не обещала его иметь.
 */

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/exemt/placitum-captcha/internal/protocol"
)

type wireAction struct {
	Properties struct {
		Do    struct{ Enum []string } `json:"do"`
		Apply struct{ Enum []string } `json:"apply"`
	} `json:"properties"`

	AllOf []struct {
		If struct {
			Properties struct {
				Do struct {
					Const string `json:"const"`
				} `json:"do"`
			} `json:"properties"`
		} `json:"if"`

		Then struct {
			Properties struct {
				Apply struct {
					Const string   `json:"const"`
					Enum  []string `json:"enum"`
				} `json:"apply"`
			} `json:"properties"`
		} `json:"then"`
	} `json:"allOf"`
}

// wire находит контракт, поднимаясь от пакета к корню дерева.
func wire(t *testing.T) wireAction {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 8; i++ {
		path := filepath.Join(dir, "docs", "messages", "inspector.schema.json")

		raw, err := os.ReadFile(path)
		if err == nil {
			var doc struct {
				Defs struct {
					Action wireAction `json:"action"`
				} `json:"$defs"`
			}

			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatalf("%s: %v", path, err)
			}

			return doc.Defs.Action
		}

		up := filepath.Dir(dir)
		if up == dir {
			break
		}

		dir = up
	}

	t.Skip("docs/messages/inspector.schema.json недоступна: контракта в этом дереве нет")

	return wireAction{}
}

// Наши константы -- ровно те слова, что принимает провод. Лишнее здесь так же
// плохо, как недостающее: глагол, которого на проводе нет, до нас не доедет, а
// правило с ним загрузчик примет.
func TestVerbsAndAxesMatchTheWire(t *testing.T) {
	action := wire(t)

	ours := []string{
		protocol.DoChallenge, protocol.DoThreshold,
		protocol.DoSkip, protocol.DoReauth, protocol.DoNote,
		protocol.DoMutate,
		protocol.DoActive, protocol.DoPassive, protocol.DoOff, protocol.DoVote,
		protocol.DoAudit, protocol.DoArchive, protocol.DoMark,
		protocol.DoScore, protocol.DoBan,
	}

	assertSameSet(t, "глаголы", ours, action.Properties.Do.Enum)

	axes := []string{
		protocol.ApplyRequest, protocol.ApplyIP,
		protocol.ApplyASN, protocol.ApplySession,
		protocol.ApplyConn, protocol.ApplyResponse,
	}

	assertSameSet(t, "оси", axes, action.Properties.Apply.Enum)
}

/*
 * Матрица осей note против провода. Фильтра осей в правилах больше нет --
 * ось называет сама просьба, а решение переводит её в корзину
 * (decide.Asked.note). Если на проводе у note появится новая ось, этот тест
 * обязан упасть: иначе просьба с ней будет молча падать в no_counter.
 */
func TestNoteAxesMatchTheWire(t *testing.T) {
	action := wire(t)

	for _, block := range action.AllOf {
		if block.If.Properties.Do.Const != protocol.DoNote {
			continue
		}

		want := block.Then.Properties.Apply.Enum
		if c := block.Then.Properties.Apply.Const; c != "" {
			want = []string{c}
		}

		if len(want) == 0 {
			continue
		}

		// Оси, которые мы умеем превращать в корзины, плюс request -- он
		// корзины не имеет осознанно и в исходе честно зовётся no_counter.
		ours := []string{
			protocol.ApplyRequest, protocol.ApplyIP,
			protocol.ApplyASN, protocol.ApplySession,
		}

		assertSameSet(t, "оси note", ours, want)
	}
}

// Глагол чужого инспектора мы принять не можем, и загрузчик обязан это сказать.
// Проверяется здесь, рядом с матрицей: список «наших» глаголов -- часть того же
// словаря, и разъезжается он вместе с ним.
func TestReauthIsNotOursToApply(t *testing.T) {
	err := validatePrior(0, PriorRule{From: "auth", Accept: []string{protocol.DoReauth}})
	if err == nil {
		t.Fatal("reauth принят: он адресован auth, применить его нам нечем")
	}
}

func assertSameSet(t *testing.T, what string, got, want []string) {
	t.Helper()

	a := append([]string(nil), got...)
	b := append([]string(nil), want...)

	sort.Strings(a)
	sort.Strings(b)

	if len(a) != len(b) {
		t.Fatalf("%s: у нас %v, на проводе %v", what, a, b)
	}

	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("%s: у нас %v, на проводе %v", what, a, b)
		}
	}
}
