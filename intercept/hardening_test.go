package intercept

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/Autumn-27/artex/config"
	"github.com/Autumn-27/artex/db"
)

func openDB(t *testing.T) *db.DB {
	t.Helper()
	dsn, _, err := config.PostgresDSN()
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func bashInput(cmd string) []byte {
	b, _ := json.Marshal(map[string]string{"command": cmd})
	return b
}

func TestSeededRulesCatchRecursiveDeleteSpellings(t *testing.T) {
	ic := New(openDB(t))
	for _, cmd := range []string{
		`rm -rf /opt/x`,
		`rm -r -f ./x`,
		`rm -f -r ./x`,
		`r''m -rf /opt/x`,
		`r\m -rf /opt/x`,
		`find /opt/x -delete`,
		`python3 -c "import shutil;shutil.rmtree('/opt/x')"`,
	} {
		if dec, hit := ic.Match("Bash", bashInput(cmd)); !hit || dec.Action != "deny" {
			t.Errorf("%q: hit=%v action=%q", cmd, hit, dec.Action)
		}
	}
	for _, cmd := range []string{`ls -la`, `rm ./one-file`, `curl https://example.com`, `find . -name '*.go'`} {
		if dec, hit := ic.Match("Bash", bashInput(cmd)); hit && dec.Action == "deny" {
			t.Errorf("%q wrongly denied by %q", cmd, dec.RuleName)
		}
	}
}

func TestRulesSeeThroughJSONEscapes(t *testing.T) {
	ic := New(openDB(t))
	escaped := []byte("{\"command\":\"" + string(rune(92)) + "u0072m -rf /opt/x\"}")
	if dec, hit := ic.Match("Bash", escaped); !hit || dec.Action != "deny" {
		t.Fatalf("hit=%v action=%q", hit, dec.Action)
	}
}

func TestInterceptFailsClosedWhenDatabaseUnavailable(t *testing.T) {
	d := openDB(t)
	ic := New(d)
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if !ic.IsToolEnabled("Bash") {
		t.Error("an unreadable tool list must not skip interception")
	}
	if dec, hit := ic.Match("Bash", bashInput("ls")); !hit || dec.Action != "deny" {
		t.Errorf("Match: hit=%v action=%q", hit, dec.Action)
	}
	if dec, hit := ic.CheckTargets(context.Background(), "Bash", bashInput("curl https://x.example")); !hit || dec.Action != "deny" {
		t.Errorf("CheckTargets: hit=%v action=%q", hit, dec.Action)
	}
}

func TestBrokenRegexEscalatesInsteadOfDisappearing(t *testing.T) {
	broken := compiledRule{InterceptRule: db.InterceptRule{ID: 7, Name: "bad", Action: "deny", MatchTarget: "tool_input", MatchType: "regex"}, broken: true}
	ic := &Interceptor{cached: []compiledRule{broken}, enabledTools: map[string]bool{}}
	dec, hit := ic.Match("Bash", bashInput("ls"))
	if !hit || dec.Action != "ask" || !dec.TimeoutEnabled || dec.TimeoutAction != "deny" {
		t.Fatalf("hit=%v dec=%+v", hit, dec)
	}
	broken.Action = "allow"
	ic.cached = []compiledRule{broken}
	if dec, hit := ic.Match("Bash", bashInput("ls")); hit {
		t.Fatalf("a broken allow rule must not grant anything: %+v", dec)
	}
}

func TestCorruptToolListFallsBackToDefaults(t *testing.T) {
	d := openDB(t)
	const key = "intercept_enabled_tools"
	old, had, err := d.GetSetting(key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if had {
			_ = d.SetSetting(key, old)
		} else {
			_, _ = d.Exec(`DELETE FROM settings WHERE key=$1`, key)
		}
	})
	if err := d.SetSetting(key, "{not json"); err != nil {
		t.Fatal(err)
	}
	if !New(d).IsToolEnabled("Bash") {
		t.Fatal("corrupt setting disabled interception")
	}
}

func TestExternalToolsAreInterceptedByDefault(t *testing.T) {
	d := openDB(t)
	ic := New(d)
	if !ic.IsToolEnabled("mcp__browser__navigate") {
		t.Error("MCP tools should enter the rule path")
	}
	key := fmt.Sprintf("custom_%d", time.Now().UnixNano())
	if err := d.CreateCustomTool(&db.Tool{Key: key, Description: "d", Kind: "command", Enabled: true, Exec: json.RawMessage(`{"command":"id"}`)}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteCustomTool(key) })
	if !ic.IsToolEnabled(key) {
		t.Error("custom tools should enter the rule path")
	}
	if ic.IsToolEnabled("list_findings") {
		t.Error("built-in platform tools stay opt-in")
	}
}

func TestJudgeFailActionDefaultsToHuman(t *testing.T) {
	if defaultJudgeFailAction != "ask" {
		t.Fatalf("default=%q", defaultJudgeFailAction)
	}
}

func TestCheckTargetsAppliesAssetRules(t *testing.T) {
	d := openDB(t)
	ic := New(d)
	rule, err := d.CreateAssetInterceptRule("exact_domain", "out-of-scope.example", "test", true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteAssetInterceptRule(rule.ID) })

	for _, cmd := range []string{
		`curl https://out-of-scope.example/x`,
		`nmap out-of-scope.example`,
		`curl 'https://out-of-scope.example'`,
		`cu''rl https://out-of''-scope.example/`,
	} {
		if dec, hit := ic.CheckTargets(context.Background(), "Bash", bashInput(cmd)); !hit || dec.Action != "deny" {
			t.Errorf("%q: hit=%v dec=%+v", cmd, hit, dec)
		}
	}
	if _, hit := ic.CheckTargets(context.Background(), "Bash", bashInput(`curl https://fine.example`)); hit {
		t.Error("unrelated target denied")
	}
	if _, hit := ic.CheckTargets(context.Background(), "Write", bashInput(`see https://out-of-scope.example`)); hit {
		t.Error("file tools do not generate traffic")
	}
}

func TestTaskAllowlistOnlyJudgesExplicitURLs(t *testing.T) {
	d := openDB(t)
	task, err := d.CreateTaskWithOptions("allowlist", "goal", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	if _, err := d.Assets().CreateTaskInterceptRule(task.ID, "allow", "exact_domain", "in-scope.example", "", true); err != nil {
		t.Fatal(err)
	}
	ic := New(d)
	ctx := WithTaskContext(context.Background(), strconv.FormatInt(task.ID, 10), "w", nil)

	if _, hit := ic.CheckTargets(ctx, "Bash", bashInput(`curl https://in-scope.example/a`)); hit {
		t.Error("allowed URL denied")
	}
	if dec, hit := ic.CheckTargets(ctx, "Bash", bashInput(`curl https://elsewhere.example/a`)); !hit || dec.Action != "deny" {
		t.Errorf("URL outside the allowlist: hit=%v", hit)
	}
	// Tokens that merely look like hosts must not trip a default-deny list.
	for _, cmd := range []string{`python3 report.py`, `pip install pkg==1.2.3.4`, `curl http://127.0.0.1:8080/x`, `curl http://localhost/x`} {
		if dec, hit := ic.CheckTargets(ctx, "Bash", bashInput(cmd)); hit {
			t.Errorf("%q denied: %s", cmd, dec.Message)
		}
	}
}
