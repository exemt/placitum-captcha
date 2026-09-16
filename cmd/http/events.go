package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/exemt/placitum-captcha/internal/buckets"
	"github.com/exemt/placitum-captcha/internal/config"
)

func tiersOf(p *config.Profile) map[string]buckets.Tier {
	return map[string]buckets.Tier{
		buckets.KindIP:     {Max: p.Buckets.IP.Max, Loss: p.Buckets.IP.Loss},
		buckets.KindSess:   {Max: p.Buckets.Sess.Max, Loss: p.Buckets.Sess.Loss},
		buckets.KindNet:    {Max: p.Buckets.ASNNet.Max, Loss: p.Buckets.ASNNet.Loss},
		buckets.KindRouter: {Max: p.Buckets.ASNRouter.Max, Loss: p.Buckets.ASNRouter.Loss},
	}
}

func sessKeyOf(sealed string) string {
	if sealed == "" {
		return ""
	}

	sum := sha256.Sum256([]byte(sealed))

	return hex.EncodeToString(sum[:8])
}

func (s *server) fired(ctx context.Context, p *config.Profile, on, clientIP,
	sealed, cid string) {
	rules := p.RulesFor(on, "", "")

	if len(rules) == 0 {
		return
	}

	var network, router string

	for _, r := range rules {
		if r.Charge == buckets.KindNet || r.Charge == buckets.KindRouter {
			network, router = s.resolver.Resolve(ctx, clientIP)

			break
		}
	}

	tiers := tiersOf(p)

	keyOf := func(kind string) string {
		switch kind {
		case buckets.KindIP:
			return buckets.IPKey(clientIP)
		case buckets.KindSess:
			return sessKeyOf(sealed)
		case buckets.KindNet:
			return network
		case buckets.KindRouter:
			return router
		}

		return ""
	}

	var charges []buckets.Charge

	for _, r := range rules {
		switch {
		case r.Charge != "":
			if key := keyOf(r.Charge); key != "" && tiers[r.Charge].Enabled() {
				charges = append(charges, buckets.Charge{
					Ref: buckets.Ref{Kind: r.Charge, Key: key},
					Add: float64(r.Percent) / 100 * tiers[r.Charge].Max,
				})
			}

		case r.List != "":
			s.writeList(ctx, r, on, clientIP, cid)
		}
	}

	if len(charges) > 0 {
		if _, err := s.buckets.Apply(ctx, p.Name, tiers, charges, nil); err != nil {
			s.log.Warn("buckets charge failed", "profile", p.Name, "error", err.Error())
		}
	}
}

func (s *server) writeList(ctx context.Context, r config.EventRule, on, clientIP, cid string) {
	if s.list == nil {
		return
	}

	var values []string

	switch r.Write {
	case config.WriteCID:
		if cid != "" {
			values = []string{cid}
		}

	case config.WriteNet, config.WriteNetAll, config.WriteASN:
		vals, err := s.resolver.Write(ctx, r.Write, clientIP)
		if err != nil {
			s.log.Warn("list write failed: geo unavailable",
				"set", r.List, "write", r.Write, "addr", clientIP, "error", err.Error())

			return
		}

		values = vals

	default:
		if clientIP != "" {
			values = []string{clientIP}
		}
	}

	if len(values) == 0 {
		return
	}

	reason := r.Code

	if reason == "" {
		reason = "CAPTCHA_" + on
	}

	if err := s.list.AddMany(r.List, values, r.TTL.D(), reason); err != nil {
		s.log.Warn("list write failed",
			"set", r.List, "write", r.Write, "count", len(values), "first", values[0],
			"error", err.Error())
	}
}
