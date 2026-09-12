/*
 * Проба: публикует сообщение инспекции на subject и ждёт вердикт.
 *
 *     captcha-probe --profile _probe --expect redirect
 *
 * Ходит тем же путём, что модуль, и потому проверяет живой инспектор целиком:
 * шину, очередь, разбор сообщения и лестницу вердикта. Cookie у неё нет и
 * быть не может -- обменник собирает модуль. Профиль default без счёта ответил
 * бы allow, поэтому healthcheck зовёт _probe: тот же профиль с when: always.
 *
 * --score подставляет score.total в сообщение -- поле протокола; капча его
 * больше не читает, но проба собирает провод честно.
 */

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-captcha/internal/protocol"
)

func main() {
	var (
		servers = flag.String("servers", env("NATS_URL", "nats://127.0.0.1:4222"),
			"адреса шины через запятую")
		subject = flag.String("subject", env("WAF_CAPTCHA_SUBJECT", "waf.req.captcha"),
			"subject инспектора")
		name = flag.String("inspector", env("WAF_CAPTCHA_NAME", "captcha"),
			"имя инспектора в сообщении")
		uri      = flag.String("uri", "/healthcheck", "путь запроса")
		method   = flag.String("method", "GET", "метод запроса")
		clientIP = flag.String("client-ip", "127.0.0.1", "conn.client_ip")
		profile  = flag.String("profile", "_probe", "значение route.profile")
		score    = flag.Int("score", 0, "score.total в сообщении")
		reason   = flag.String("prior", "",
			"prior: сосед просит проверку, inspector=code, например ip=IP_GREYLIST")
		expect  = flag.String("expect", "", "ожидаемый вердикт: allow, redirect, deny")
		timeout = flag.Duration("timeout", time.Second, "сколько ждать ответа")
		quiet   = flag.Bool("quiet", false, "не печатать ответ, только код возврата")
	)

	flag.Parse()

	err := run(*servers, *subject, *name, *uri, *method, *clientIP, *profile, *reason,
		*score, *expect, *timeout, *quiet)
	if err != nil {
		fmt.Fprintln(os.Stderr, "probe:", err)
		os.Exit(1)
	}
}

func run(servers, subject, name, uri, method, clientIP, profile, prior string,
	score int, expect string, timeout time.Duration, quiet bool) error {

	nc, err := nats.Connect(servers, nats.Timeout(timeout), nats.NoReconnect())
	if err != nil {
		return err
	}

	defer nc.Close()

	payload, err := json.Marshal(request(name, uri, method, clientIP, profile, prior, score,
		timeout))
	if err != nil {
		return err
	}

	msg, err := nc.Request(subject, payload, timeout)
	if err != nil {
		return fmt.Errorf("no verdict from %s: %w", subject, err)
	}

	var reply protocol.Reply

	if err := json.Unmarshal(msg.Data, &reply); err != nil {
		return fmt.Errorf("malformed reply: %w", err)
	}

	if !quiet {
		out, _ := json.Marshal(reply)
		fmt.Println(string(out))
	}

	if expect != "" && reply.Verdict != expect {
		return fmt.Errorf("verdict is %q, expected %q", reply.Verdict, expect)
	}

	return nil
}

func request(name, uri, method, clientIP, profile, prior string, score int,
	timeout time.Duration) *protocol.Request {

	path, args, _ := strings.Cut(uri, "?")

	req := &protocol.Request{
		V:          protocol.Version,
		RID:        fmt.Sprintf("%016x", time.Now().UnixNano()),
		Phase:      protocol.PhaseRequest,
		Inspector:  name,
		DeadlineMS: int(timeout.Milliseconds()),
		Node:       "probe",
		Conn: protocol.Conn{
			ClientIP:   clientIP,
			ClientPort: 12345,
			ServerIP:   "127.0.0.1",
			ServerPort: 8080,
		},
		HTTP: protocol.HTTP{
			Method:   method,
			Scheme:   "http",
			Host:     "probe.local",
			URI:      path,
			ArgsSize: int64(len(args)),
			Version:  "HTTP/1.1",
		},
		Needs: []string{protocol.NeedHeaders},
		Route: protocol.Route{ServerName: "probe.local", Location: "/", Profile: profile},
		Score: protocol.ScoreState{Total: score, DenyAt: 100},
	}

	if prior != "" {
		insp, code, _ := strings.Cut(prior, "=")
		req.Prior = []protocol.PriorVerdict{{
			Phase:     protocol.PhaseRequest,
			Inspector: insp,
			Verdict:   protocol.VerdictAllow,
			Actions: []protocol.Action{{
				Do:    protocol.DoChallenge,
				Apply: protocol.ApplyRequest,
				Code:  code,
			}},
		}}
	}

	return req
}

func env(name, def string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}

	return def
}
