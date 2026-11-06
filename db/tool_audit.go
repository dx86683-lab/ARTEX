package db

import (
	"fmt"
	"time"
)

const (
	toolAuditRetention  = 90 * 24 * time.Hour
	toolAuditMaxCommand = 8 << 10
)

// ensureToolAudit creates the audit table and applies retention. It runs at startup
// only, so a long-lived install grows by at most the traffic between restarts.
func (d *DB) ensureToolAudit() error {
	if _, err := d.Exec(`
CREATE TABLE IF NOT EXISTS tool_audit (
  id      BIGSERIAL PRIMARY KEY,
  ts      BIGINT NOT NULL,
  task_id TEXT NOT NULL DEFAULT '',
  tool    TEXT NOT NULL,
  action  TEXT NOT NULL,
  reason  TEXT NOT NULL DEFAULT '',
  command TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_tool_audit_task ON tool_audit(task_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_tool_audit_ts ON tool_audit(ts);`); err != nil {
		return err
	}
	_, err := d.Exec(`DELETE FROM tool_audit WHERE ts < $1`, time.Now().Add(-toolAuditRetention).Unix())
	return err
}

// ToolAuditEntry is one gated tool call and its final outcome.
type ToolAuditEntry struct {
	TS      int64  `json:"ts"`
	Tool    string `json:"tool"`
	Action  string `json:"action"`
	Reason  string `json:"reason,omitempty"`
	Command string `json:"command,omitempty"`
}

// AppendToolAudit stores the outcome of one gated call.
func (d *DB) AppendToolAudit(taskID, tool, action, reason, command string) error {
	if len(command) > toolAuditMaxCommand {
		command = fmt.Sprintf("%s...[truncated %d bytes]", toValidUTF8Prefix(command, toolAuditMaxCommand), len(command)-toolAuditMaxCommand)
	}
	_, err := d.Exec(`INSERT INTO tool_audit(ts, task_id, tool, action, reason, command) VALUES ($1,$2,$3,$4,$5,$6)`,
		time.Now().Unix(), taskID, tool, action, reason, command)
	return err
}

// ListToolAudit returns a task's most recent entries, oldest first.
func (d *DB) ListToolAudit(taskID string, limit int) ([]ToolAuditEntry, error) {
	rows, err := d.Query(`
SELECT ts, tool, action, reason, command FROM (
  SELECT id, ts, tool, action, reason, command FROM tool_audit
  WHERE task_id = $1 ORDER BY id DESC LIMIT $2
) recent ORDER BY id ASC`, taskID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ToolAuditEntry{}
	for rows.Next() {
		var e ToolAuditEntry
		if err := rows.Scan(&e.TS, &e.Tool, &e.Action, &e.Reason, &e.Command); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// toValidUTF8Prefix cuts s to at most n bytes without splitting a rune; Postgres rejects
// invalid UTF-8 in TEXT columns.
func toValidUTF8Prefix(s string, n int) string {
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}

// seedDefaultInterceptRulesV4 covers recursive-delete spellings the v1 rules miss. It
// adds a rule instead of editing v1 so an operator's changes to v1 survive.
func (d *DB) seedDefaultInterceptRulesV4() error {
	if v, _, _ := d.GetSetting("intercept_default_rules_v4"); v == "done" {
		return nil
	}
	const name = "[内置] 递归删除的其他写法"
	if _, err := d.Exec(`
INSERT INTO intercept_rules(name, enabled, priority, match_target, match_type, pattern, action, message, timeout_enabled, timeout_seconds, timeout_action)
SELECT $1::text, true, 100, 'tool_input', 'regex', $2::text, 'deny', $3::text, false, 60, 'deny'
WHERE NOT EXISTS (SELECT 1 FROM intercept_rules WHERE name = $1::text)`,
		name,
		`(?i)\brm\b.{0,80}\s-[a-z]*r[a-z]*\s.{0,40}-[a-z]*f|\brm\b.{0,80}\s-[a-z]*f[a-z]*\s.{0,40}-[a-z]*r|\bfind\b.{0,200}\s-delete\b|\bshutil\.rmtree\b`,
		"禁止递归删除（rm -r -f / find -delete / shutil.rmtree），可能永久损坏系统或靶机环境",
	); err != nil {
		return err
	}
	return d.SetSetting("intercept_default_rules_v4", "done")
}
