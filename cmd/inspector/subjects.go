package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/exemt/placitum-captcha/internal/buckets"
	"github.com/exemt/placitum-captcha/internal/config"
	"github.com/exemt/placitum-captcha/internal/decide"
	"github.com/exemt/placitum-captcha/internal/overload"
	"github.com/exemt/placitum-captcha/internal/protocol"
	"github.com/exemt/placitum-captcha/internal/queue"
	"github.com/exemt/placitum-captcha/internal/token"
	"github.com/exemt/placitum-shared/netinfo"
)

type geoResolver interface {
	Resolve(ctx context.Context, raw string) (network, router string)
	Lookup(ctx context.Context, addr netip.Addr, expand bool) (netinfo.Info, error)
}

type listWriter interface {
	Add(name, value string, ttl time.Duration, reason string) error
	AddMany(name string, values []string, ttl time.Duration, reason string) error
}

type subject struct {
	ip     string
	sess   string
	net    string
	router string
}

func (s subject) key(kind string) string {
	switch kind {
	case buckets.KindIP:
		return s.ip
	case buckets.KindSess:
		return s.sess
	case buckets.KindNet:
		return s.net
	case buckets.KindRouter:
		return s.router
	}

	return ""
}

var bucketKinds = []string{
	buckets.KindIP, buckets.KindSess, buckets.KindNet, buckets.KindRouter,
}

var clearedKinds = []string{buckets.KindSess}

func tiersOf(p *config.Profile) map[string]buckets.Tier {
	return map[string]buckets.Tier{
		buckets.KindIP:     {Max: p.Buckets.IP.Max, Loss: p.Buckets.IP.Loss},
		buckets.KindSess:   {Max: p.Buckets.Sess.Max, Loss: p.Buckets.Sess.Loss},
		buckets.KindNet:    {Max: p.Buckets.ASNNet.Max, Loss: p.Buckets.ASNNet.Loss},
		buckets.KindRouter: {Max: p.Buckets.ASNRouter.Max, Loss: p.Buckets.ASNRouter.Loss},
	}
}

func (h *handler) subjectsOf(ctx context.Context, p *config.Profile, clientIP, clearance string) subject {
	var s subject

	if p.Buckets.IP.Enabled() {
		s.ip = buckets.IPKey(clientIP)
	}

	if p.Buckets.Sess.Enabled() && clearance != "" {
		sum := sha256.Sum256([]byte(clearance))
		s.sess = hex.EncodeToString(sum[:8])
	}

	if p.Buckets.ASNNet.Enabled() || p.Buckets.ASNRouter.Enabled() {
		network, router := h.resolver.Resolve(ctx, clientIP)

		if p.Buckets.ASNNet.Enabled() {
			s.net = network
		}

		if p.Buckets.ASNRouter.Enabled() {
			s.router = router
		}
	}

	return s
}

func chargesOf(s subject, tiers map[string]buckets.Tier, notes []decide.Note) []buckets.Charge {
	var out []buckets.Charge

	for _, n := range notes {
		key := s.key(n.Axis)
		tier := tiers[n.Axis]

		if key == "" || !tier.Enabled() {
			continue
		}

		out = append(out, buckets.Charge{
			Ref: buckets.Ref{Kind: n.Axis, Key: key},
			Add: float64(n.Percent) / 100 * tier.Max,
		})
	}

	return out
}

func readsOf(s subject, tiers map[string]buckets.Tier, cleared bool) []buckets.Ref {
	kinds := bucketKinds
	if cleared {
		kinds = clearedKinds
	}

	var out []buckets.Ref

	for _, kind := range kinds {
		if key := s.key(kind); key != "" && tiers[kind].Enabled() {
			out = append(out, buckets.Ref{Kind: kind, Key: key})
		}
	}

	return out
}

func percentsOf(levels []buckets.Level) map[string]float64 {
	if len(levels) == 0 {
		return nil
	}

	out := make(map[string]float64, len(levels))

	for _, l := range levels {
		out[l.Kind] = l.Percent
	}

	return out
}

func (h *handler) fireBucketFull(ctx context.Context, p *config.Profile, subj subject, clientIP string,
	levels []buckets.Level, next string) ([]protocol.Action, error) {

	if len(p.Rules) == 0 {
		return nil, nil
	}

	var actions []protocol.Action
	var charges []buckets.Charge
	tiers := tiersOf(p)

	for _, l := range levels {
		tier := p.Buckets.Tier(l.Kind)

		steps := []struct {
			on string
			at int
		}{
			{config.OnBucketCaptcha, tier.CaptchaAt},
			{config.OnBucketBan, tier.BanAt},
		}

		for _, step := range steps {
			if step.at == 0 || l.Percent < float64(step.at) {
				continue
			}

			for _, r := range p.RulesFor(step.on, l.Kind, next) {
				switch {
				case r.Do != "":
					actions = append(actions, askOf(r))

				case r.List != "":
					if err := h.writeList(ctx, r, clientIP, "", code(r, l.Kind)); err != nil {
						return nil, err
					}

				case r.Charge != "":
					if key := subj.key(r.Charge); key != "" && tiers[r.Charge].Enabled() {
						charges = append(charges, buckets.Charge{
							Ref: buckets.Ref{Kind: r.Charge, Key: key},
							Add: float64(r.Percent) / 100 * tiers[r.Charge].Max,
						})
					}
				}
			}
		}
	}

	if len(charges) > 0 {
		if _, err := h.buckets.Apply(context.Background(), p.Name, tiers,
			charges, nil); err != nil {
			h.log.Warn("buckets charge failed", "profile", p.Name, "error", err.Error())
		}
	}

	return actions, nil
}

func (h *handler) fireClient(ctx context.Context, p *config.Profile, subj subject, clientIP, on, next string,
	clr *token.Clearance) ([]protocol.Action, error) {

	rules := p.RulesFor(on, "", next)

	if len(rules) == 0 {
		return nil, nil
	}

	var cid string

	if clr != nil {
		cid = clr.CID
	}

	var actions []protocol.Action
	var charges []buckets.Charge
	tiers := tiersOf(p)

	for _, r := range rules {
		switch {
		case r.Do != "":
			actions = append(actions, askOf(r))

		case r.List != "":
			reason := r.Code
			if reason == "" {
				reason = "CAPTCHA_" + strings.ToUpper(on)
			}

			if err := h.writeList(ctx, r, clientIP, cid, reason); err != nil {
				return nil, err
			}

		case r.Charge != "":
			key := subj.key(r.Charge)

			if key == "" || !tiers[r.Charge].Enabled() {
				continue
			}

			charges = append(charges, buckets.Charge{
				Ref: buckets.Ref{Kind: r.Charge, Key: key},
				Add: float64(r.Percent) / 100 * tiers[r.Charge].Max,
			})
		}
	}

	if len(charges) > 0 {
		if _, err := h.buckets.Apply(context.Background(), p.Name, tiers,
			charges, nil); err != nil {
			h.log.Warn("buckets charge failed", "profile", p.Name, "error", err.Error())
		}
	}

	return actions, nil
}

func (h *handler) writeList(ctx context.Context, r config.EventRule, clientIP, cid, reason string) error {
	if h.lists == nil {
		return nil
	}

	ttl := r.TTL.D()

	var values []string

	switch r.Write {
	case config.WriteCID:
		if cid == "" {
			return nil
		}

		values = []string{cid}

	case config.WriteNet, config.WriteNetAll, config.WriteASN:
		vals, err := h.resolveWrite(ctx, r.Write, clientIP)
		if err != nil {
			return err
		}

		values = vals

	default:
		values = []string{clientIP}
	}

	if len(values) == 0 {
		h.log.Warn("list write skipped: coder knows nothing about the address",
			"set", r.List, "write", r.Write, "addr", clientIP)

		return nil
	}

	if err := h.lists.AddMany(r.List, values, ttl, reason); err != nil {
		h.log.Warn("list write failed",
			"set", r.List, "write", r.Write, "count", len(values), "error", err.Error())

		return nil
	}

	h.log.Info("list write",
		"set", r.List, "write", r.Write, "count", len(values),
		"first", values[0], "ttl_s", int64(ttl.Seconds()), "reason", reason, "addr", clientIP)

	return nil
}

func (h *handler) resolveWrite(ctx context.Context, write, clientIP string) ([]string, error) {
	addr, err := netip.ParseAddr(clientIP)
	if err != nil {
		return nil, nil
	}

	info, err := h.resolver.Lookup(ctx, addr, write == config.WriteASN)
	if err != nil {
		return nil, fmt.Errorf("write %s for %s: %w", write, clientIP, err)
	}

	return netinfo.Values(info, write), nil
}

func askOf(r config.EventRule) protocol.Action {
	out := protocol.Action{
		To:      r.To,
		Do:      r.Do,
		Apply:   r.Axis(),
		Phase:   r.Phase,
		Code:    r.Code,
		Counter: r.Counter,
		Marker:  r.Marker,
		Group:   r.Group,
		Set:     r.Set,
		Headers: r.Headers,
		Args:    r.Args,
		Body:    r.Body,
	}

	if r.Do == protocol.DoArchive && r.Set == "on" {
		if seconds := int64(r.TTL.D().Seconds()); seconds > 0 {
			out.TTL = &seconds
		}

		if len(r.When) > 0 {
			when, _ := protocol.CheckArchiveWhen(r.When)
			out.When = when
		}
	}

	if r.Delta != nil {
		out.Delta = *r.Delta
	}

	if r.Value != nil {
		out.Value = *r.Value
	}

	return out
}

func code(r config.EventRule, kind string) string {
	if r.Code != "" {
		return r.Code
	}

	return "CAPTCHA_BUCKET_" + kind
}

func (h *handler) fireOverload(ctx context.Context, p *config.Profile, subj subject, clientIP string,
	fill int, shed bool) ([]protocol.Action, error) {

	var actions []protocol.Action
	var charges []buckets.Charge
	tiers := tiersOf(p)

	for _, r := range p.RulesFor(config.OnOverload, "", "") {
		if !overload.Fires(overload.At(r.At), fill, shed) {
			continue
		}

		switch {
		case r.Do != "":
			actions = append(actions, askOf(r))

		case r.List != "":
			reason := r.Code
			if reason == "" {
				reason = queue.ReasonQueueLimit
			}

			if err := h.writeList(ctx, r, clientIP, "", reason); err != nil {
				return nil, err
			}

		case r.Charge != "":
			key := subj.key(r.Charge)

			if key == "" || !tiers[r.Charge].Enabled() {
				continue
			}

			charges = append(charges, buckets.Charge{
				Ref: buckets.Ref{Kind: r.Charge, Key: key},
				Add: float64(r.Percent) / 100 * tiers[r.Charge].Max,
			})
		}
	}

	if len(charges) > 0 {
		if _, err := h.buckets.Apply(context.Background(), p.Name, tiers,
			charges, nil); err != nil {
			h.log.Warn("buckets charge failed", "profile", p.Name, "error", err.Error())
		}
	}

	return actions, nil
}

func chargesOnOverload(p *config.Profile) bool {
	for _, r := range p.RulesFor(config.OnOverload, "", "") {
		if r.Charge != "" {
			return true
		}
	}

	return false
}
