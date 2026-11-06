package db

import (
	"strings"
	"testing"
)

func TestToValidUTF8PrefixDoesNotSplitRunes(t *testing.T) {
	if got := toValidUTF8Prefix("密码", 4); got != "密" {
		t.Fatalf("got %q", got)
	}
	if got := toValidUTF8Prefix("abcdef", 3); got != "abc" {
		t.Fatalf("got %q", got)
	}
	long := strings.Repeat("密", toolAuditMaxCommand)
	if cut := toValidUTF8Prefix(long, toolAuditMaxCommand); !strings.HasPrefix(long, cut) || len(cut)%3 != 0 {
		t.Fatalf("len=%d", len(cut))
	}
}
