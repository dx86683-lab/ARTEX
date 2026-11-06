package server

import (
	"log"
	"net"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/traffic"
)

const egressRulesTTL = 5 * time.Second

// newEgressGate applies the global asset block rules at the recording proxy. Unlike the
// text check on tool input this sees the real destination, however the command built it.
//
// Task-level rules are not applied: the proxy is shared and cannot tell which task a
// request belongs to. Allow rules never override block rules, so ignoring them here is
// safe. Traffic that bypasses the proxy (a command clearing HTTP_PROXY) is out of reach;
// closing that requires network-level egress control.
func newEgressGate(pg *db.DB) traffic.EgressGate {
	var (
		mu     sync.Mutex
		rules  []db.AssetInterceptRule
		loaded bool
		at     time.Time
	)
	load := func() ([]db.AssetInterceptRule, bool) {
		mu.Lock()
		defer mu.Unlock()
		if loaded && time.Since(at) < egressRulesTTL {
			return rules, true
		}
		fresh, err := pg.ListAssetInterceptRules()
		if err != nil {
			log.Printf("[traffic] 读取资产拦截规则失败: %v", err)
			return rules, loaded // a stale list beats no list
		}
		rules, loaded, at = fresh, true, time.Now()
		return rules, true
	}
	return func(host string) (bool, string) {
		current, ok := load()
		if !ok {
			return true, "资产拦截规则暂时不可用"
		}
		var domains, ips []string
		if net.ParseIP(host) != nil {
			ips = []string{host}
		} else {
			domains = []string{host}
		}
		if rule, _, hit := db.MatchAssetInterceptRules(current, domains, ips, nil); hit {
			return true, rule.Reason()
		}
		return false, ""
	}
}
