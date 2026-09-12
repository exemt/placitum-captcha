package main

import (
	"context"
	"testing"
	"time"

	"github.com/exemt/placitum-captcha/internal/config"
	"github.com/exemt/placitum-captcha/internal/protocol"
	"github.com/exemt/placitum-captcha/internal/token"
)

/*
 * Правила клиента выбираются событием: без клиренса срабатывают строки
 * uncleared и только они, с клиренсом -- строки cleared. Просьба уезжает
 * пачкой, запись в набор идёт с поводом своего события, а кука известна
 * только тому, кто её предъявил.
 */
func TestClientRulesFollowTheEvent(t *testing.T) {
	lists := &fakeLists{}
	h := testHandler(&fakeGeo{}, lists)
	minute := config.Duration(time.Minute)

	p := banProfile(
		config.EventRule{On: config.OnUncleared, To: "vlai", Do: protocol.DoActive,
			Apply: protocol.ApplyRequest, Code: "NO_CLEARANCE"},
		config.EventRule{On: config.OnUncleared, List: "seen", Write: config.WriteAddr, TTL: minute},
		config.EventRule{On: config.OnCleared, To: "vlai", Do: protocol.DoOff,
			Apply: protocol.ApplyRequest},
		config.EventRule{On: config.OnCleared, List: "seen", Write: config.WriteCID, TTL: minute},
	)

	acts, err := h.fireClient(context.Background(), p, subject{}, "8.8.8.143",
		config.OnUncleared, config.NextAllow, nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(acts) != 1 || acts[0].Do != protocol.DoActive || acts[0].Code != "NO_CLEARANCE" {
		t.Fatalf("uncleared asks %+v", acts)
	}

	if len(lists.writes) != 1 || lists.writes[0].values[0] != "8.8.8.143" ||
		lists.writes[0].reason != "CAPTCHA_UNCLEARED" {
		t.Fatalf("uncleared writes %+v", lists.writes)
	}

	lists.writes = nil

	acts, err = h.fireClient(context.Background(), p, subject{}, "8.8.8.143",
		config.OnCleared, config.NextAllow, &token.Clearance{CID: "cid-1"})
	if err != nil {
		t.Fatal(err)
	}

	if len(acts) != 1 || acts[0].Do != protocol.DoOff {
		t.Fatalf("cleared asks %+v", acts)
	}

	if len(lists.writes) != 1 || lists.writes[0].values[0] != "cid-1" ||
		lists.writes[0].reason != "CAPTCHA_CLEARED" {
		t.Fatalf("cleared writes %+v", lists.writes)
	}
}

/*
 * Решение лестницы сужает правила: цена показа виджета берётся только с
 * показа, просьба соседу -- только с пропуска, а правило без next срабатывает
 * на любом решении. У порогов корзин -- то же самое.
 */
func TestRulesFollowTheDecision(t *testing.T) {
	lists := &fakeLists{}
	h := testHandler(&fakeGeo{}, lists)
	minute := config.Duration(time.Minute)
	ctx := context.Background()

	p := banProfile(
		config.EventRule{On: config.OnUncleared, Next: config.NextAllow, To: "vlai",
			Do: protocol.DoActive, Apply: protocol.ApplyRequest},
		config.EventRule{On: config.OnUncleared, Next: config.NextChallenge, List: "shown",
			Write: config.WriteAddr, TTL: minute},
		config.EventRule{On: config.OnUncleared, Do: protocol.DoMark, Marker: "no clearance",
			Apply: protocol.ApplyRequest},
		config.EventRule{On: config.OnBucketBan, Bucket: "ip", Next: config.NextChallenge,
			List: "ban", Write: config.WriteAddr, TTL: minute},
	)

	// Пропустила: просьба соседу и метка; записи о показе нет.
	acts, err := h.fireClient(ctx, p, subject{}, "8.8.8.143", config.OnUncleared, config.NextAllow, nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(acts) != 2 || acts[0].Do != protocol.DoActive || acts[1].Do != protocol.DoMark ||
		len(lists.writes) != 0 {
		t.Fatalf("let through: asks %+v, writes %+v", acts, lists.writes)
	}

	// Показала виджет: метка и запись показа; просьбы соседу нет.
	acts, err = h.fireClient(ctx, p, subject{}, "8.8.8.143", config.OnUncleared, config.NextChallenge, nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(acts) != 1 || acts[0].Do != protocol.DoMark ||
		len(lists.writes) != 1 || lists.writes[0].set != "shown" {
		t.Fatalf("challenged: asks %+v, writes %+v", acts, lists.writes)
	}

	// Порог с next: challenge молчит, когда капча пропустила, и пишет, когда показала.
	lists.writes = nil

	if _, err := h.fireBucketFull(ctx, p, subject{}, "8.8.8.143", fullIP(), config.NextAllow); err != nil {
		t.Fatal(err)
	}

	if len(lists.writes) != 0 {
		t.Fatalf("threshold fired on a let-through request: %+v", lists.writes)
	}

	if _, err := h.fireBucketFull(ctx, p, subject{}, "8.8.8.143", fullIP(), config.NextChallenge); err != nil {
		t.Fatal(err)
	}

	if len(lists.writes) != 1 || lists.writes[0].set != "ban" {
		t.Fatalf("threshold writes %+v", lists.writes)
	}
}
