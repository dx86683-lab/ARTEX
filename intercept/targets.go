package intercept

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// CheckTargets applies the asset gate (global block rules plus the task's own block and
// allow rules) to the targets named in a network-capable tool call. Without this the
// gate only guards what enters the asset database: the rules exist, the UI shows them,
// and `curl https://blocked.example` still runs.
//
// It reads targets out of command text, so a command that assembles a hostname at run
// time gets past it. It catches mistakes and straightforward requests; the proxy gate
// and network-level egress control are what enforce scope against a hostile agent.
func (i *Interceptor) CheckTargets(ctx context.Context, tool string, input []byte) (Decision, bool) {
	if !i.isNetworkTool(tool) {
		return Decision{}, false
	}
	block, err := i.db.ListAssetInterceptRules()
	if err != nil {
		return targetDenied("资产拦截规则暂时不可用，无法确认目标是否在授权范围内", err)
	}
	var allow []db.AssetInterceptRule
	if raw, _ := taskInfoFromCtx(ctx); raw != "" {
		if taskID, perr := strconv.ParseInt(raw, 10, 64); perr == nil {
			tb, ta, err := i.db.Assets().TaskInterceptRulesSplit(taskID)
			if err != nil {
				return targetDenied("任务拦截规则暂时不可用，无法确认目标是否在授权范围内", err)
			}
			block = append(block, tb...)
			allow = ta
		}
	}
	t := extractTargets(inputSubjects(input))
	if rule, value, hit := db.MatchAssetInterceptRules(block, t.hosts, t.ips, t.urls); hit {
		return Decision{Action: "deny", Message: fmt.Sprintf("目标 %s %s", value, rule.Reason())}, true
	}
	// An allowlist only sees explicit URLs. Bare tokens are too ambiguous here: report.py
	// looks like a domain and 1.2.3.4 may be a version, and either would deny a harmless
	// command. Block rules can afford that noise; a default-deny list cannot.
	for _, u := range t.parsed {
		if u.loopback {
			continue
		}
		if d := db.EvaluateAssetGate(nil, allow, u.hosts, u.ips, []string{u.raw}); !d.Allowed {
			return Decision{Action: "deny", Message: fmt.Sprintf("目标 %s %s", u.raw, d.Reason)}, true
		}
	}
	return Decision{}, false
}

func targetDenied(msg string, err error) (Decision, bool) {
	log.Printf("[intercept] %s: %v", msg, err)
	return Decision{Action: "deny", Message: msg}, true
}

// isNetworkTool lists tools whose input can name a remote target. File tools are left
// out on purpose: a report quoting a blocked URL is not traffic to it.
func (i *Interceptor) isNetworkTool(tool string) bool {
	switch tool {
	case "Bash", "shell_open", "shell_send", "WebFetch":
		return true
	}
	return i.isExternalTool(tool)
}

var (
	urlPattern    = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s'"<>\\` + "`" + `)]+`)
	domainPattern = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b`)
	ipv4Pattern   = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
)

type urlTarget struct {
	raw      string
	hosts    []string
	ips      []string
	loopback bool
}

type targets struct {
	hosts, ips, urls []string
	parsed           []urlTarget
}

func extractTargets(subjects []string) targets {
	var t targets
	seen := map[string]bool{}
	add := func(dst *[]string, s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			*dst = append(*dst, s)
		}
	}
	for _, s := range subjects {
		for _, raw := range urlPattern.FindAllString(s, -1) {
			raw = strings.TrimRight(raw, ".,;:")
			if seen["url:"+raw] {
				continue
			}
			seen["url:"+raw] = true
			t.urls = append(t.urls, raw)
			u, err := url.Parse(raw)
			if err != nil || u.Hostname() == "" {
				continue
			}
			target := urlTarget{raw: raw}
			host := u.Hostname()
			if ip := net.ParseIP(host); ip != nil {
				target.ips = []string{host}
				target.loopback = ip.IsLoopback()
				add(&t.ips, host)
			} else {
				target.hosts = []string{host}
				target.loopback = strings.EqualFold(host, "localhost")
				add(&t.hosts, host)
			}
			t.parsed = append(t.parsed, target)
		}
		for _, ip := range ipv4Pattern.FindAllString(s, -1) {
			if net.ParseIP(ip) != nil {
				add(&t.ips, ip)
			}
		}
		for _, d := range domainPattern.FindAllString(s, -1) {
			if net.ParseIP(d) == nil {
				add(&t.hosts, d)
			}
		}
	}
	return t
}
