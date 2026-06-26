package permissionauditor

import "testing"

func TestAuditLowRisk(t *testing.T) {
	r := Audit([]string{"storage", "alarms"}, nil)
	if r.Overall != LevelLow && r.Overall != LevelModerate {
		t.Errorf("Overall = %s, want Low or Moderate for trivial perms", r.Overall)
	}
	for _, f := range r.Permissions {
		if f.Permission == "storage" && f.Level != LevelLow {
			t.Errorf("storage Level = %s, want Low", f.Level)
		}
	}
}

func TestAuditCriticalNativeMessaging(t *testing.T) {
	r := Audit([]string{"nativeMessaging"}, nil)
	if r.Overall != LevelCritical {
		t.Errorf("Overall = %s, want Critical for nativeMessaging", r.Overall)
	}
	if len(r.Permissions) != 1 || r.Permissions[0].Permission != "nativeMessaging" {
		t.Errorf("expected one nativeMessaging finding, got %+v", r.Permissions)
	}
}

func TestAuditCookiesAndHistory(t *testing.T) {
	r := Audit([]string{"cookies", "history"}, nil)
	if r.Overall != LevelHigh {
		t.Errorf("Overall = %s, want High for cookies+history", r.Overall)
	}
}

func TestAuditAllUrlsHost(t *testing.T) {
	r := Audit(nil, []string{"<all_urls>"})
	if len(r.Hosts) != 1 || r.Hosts[0].Level != LevelCritical {
		t.Errorf("Hosts = %+v, want one Critical for <all_urls>", r.Hosts)
	}
	if r.Overall != LevelCritical {
		t.Errorf("Overall = %s, want Critical", r.Overall)
	}
	if r.Hosts[0].Scope != "all-sites" {
		t.Errorf("Scope = %s, want all-sites", r.Hosts[0].Scope)
	}
}

func TestAuditSubdomainHost(t *testing.T) {
	r := Audit(nil, []string{"https://*.example.com/*"})
	if r.Hosts[0].Level != LevelModerate {
		t.Errorf("subdomain Level = %s, want Moderate", r.Hosts[0].Level)
	}
}

func TestAuditSingleHost(t *testing.T) {
	r := Audit(nil, []string{"https://example.com/*"})
	if r.Hosts[0].Level != LevelLow {
		t.Errorf("single host Level = %s, want Low", r.Hosts[0].Level)
	}
	if r.Hosts[0].Scope != "single-site" {
		t.Errorf("Scope = %s, want single-site", r.Hosts[0].Scope)
	}
}

func TestAuditUnknownPermission(t *testing.T) {
	r := Audit([]string{"totallyMadeUpPerm"}, nil)
	if r.Permissions[0].Level != LevelLow {
		t.Errorf("unknown perm Level = %s, want Low", r.Permissions[0].Level)
	}
	if r.Permissions[0].Category != "Unknown" {
		t.Errorf("Category = %s, want Unknown", r.Permissions[0].Category)
	}
}

func TestAuditEmpty(t *testing.T) {
	r := Audit(nil, nil)
	if r.Overall != LevelNone {
		t.Errorf("Overall = %s, want None for empty", r.Overall)
	}
	if r.Summary != "No permissions or host access declared." {
		t.Errorf("Summary = %q", r.Summary)
	}
}

func TestAuditDedupAndSort(t *testing.T) {
	r := Audit([]string{"cookies", "cookies", "alarms", "storage"}, nil)
	// Should dedupe to 3 and sort alphabetically.
	if len(r.Permissions) != 3 {
		t.Fatalf("got %d findings, want 3 (deduped): %+v", len(r.Permissions), r.Permissions)
	}
	if r.Permissions[0].Permission != "alarms" {
		t.Errorf("first sorted permission = %s, want alarms", r.Permissions[0].Permission)
	}
}

func TestAuditBlanksAndWhitespace(t *testing.T) {
	r := Audit([]string{" storage ", "", "  tabs"}, nil)
	if len(r.Permissions) != 2 {
		t.Errorf("expected 2 perms after trimming blanks, got %d: %+v", len(r.Permissions), r.Permissions)
	}
}

func TestScoreToLevelBoundaries(t *testing.T) {
	cases := []struct {
		score int
		want  Level
	}{
		{0, LevelNone}, {9, LevelNone}, {10, LevelLow}, {34, LevelLow},
		{35, LevelModerate}, {59, LevelModerate}, {60, LevelHigh}, {79, LevelHigh},
		{80, LevelCritical}, {100, LevelCritical},
	}
	for _, c := range cases {
		if got := scoreToLevel(c.score); got != c.want {
			t.Errorf("scoreToLevel(%d) = %s, want %s", c.score, got, c.want)
		}
	}
}

func TestBuildSummaryCritical(t *testing.T) {
	r := Audit([]string{"nativeMessaging"}, []string{"<all_urls>"})
	if r.Summary == "" {
		t.Error("Summary empty for critical report")
	}
	if r.Overall != LevelCritical {
		t.Errorf("Overall = %s, want Critical", r.Overall)
	}
}

func TestReportFieldsPopulated(t *testing.T) {
	r := Audit([]string{"tabs"}, []string{"https://*/*"})
	if len(r.Permissions) == 0 || len(r.Hosts) == 0 {
		t.Error("findings lists should be populated")
	}
	if r.TotalScore <= 0 {
		t.Error("TotalScore should be positive for risky manifest")
	}
	if r.Summary == "" {
		t.Error("Summary should be set")
	}
}

func TestTotalScoreCapped(t *testing.T) {
	// Worst case should never exceed 100.
	r := Audit([]string{"nativeMessaging", "webRequestBlocking"}, []string{"<all_urls>", "*://*/*"})
	if r.TotalScore > 100 {
		t.Errorf("TotalScore = %d, should be capped at 100", r.TotalScore)
	}
}
