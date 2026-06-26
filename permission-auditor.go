// Package permissionauditor audits the permissions declared by a Chromium
// extension (Manifest V2 or V3) and assigns each a risk level with a
// human-readable rationale.
//
// It is the risk-scoring engine behind the extension safety review tools at
// https://zovo.one: given the parsed permissions and host match patterns, it
// returns a per-permission breakdown, an overall risk level, and a summary the
// UI renders directly.
//
// The package is designed to pair with
// github.com/theluckystrike/crx-manifest-parser but takes plain string slices
// so it can be used standalone.
//
// Example:
//
//	report := permissionauditor.Audit(
//		[]string{"tabs", "cookies", "storage"},
//		[]string{"https://*/*"},
//	)
//	fmt.Println(report.Overall) // High
package permissionauditor

import (
	"sort"
	"strings"
)

// Level is the categorical risk level for a single permission or the manifest.
type Level string

const (
	LevelNone     Level = "None"
	LevelLow      Level = "Low"
	LevelModerate Level = "Moderate"
	LevelHigh     Level = "High"
	LevelCritical Level = "Critical"
)

// PermissionFinding describes the risk verdict for one declared permission.
type PermissionFinding struct {
	// Permission is the permission identifier as declared (e.g. "tabs").
	Permission string

	// Level is the categorical risk level.
	Level Level

	// Score is the numeric risk contribution (0-100) used for ranking.
	Score int

	// Reason is a short human-readable explanation of the risk.
	Reason string

	// Category groups related permissions (e.g. "Privacy", "DataAccess").
	Category string
}

// HostFinding describes the risk verdict for one host match pattern.
type HostFinding struct {
	// Pattern is the match pattern as declared (e.g. "https://*/*").
	Pattern string

	// Level is the categorical risk level.
	Level Level

	// Score is the numeric risk contribution (0-100).
	Score int

	// Reason is a short explanation.
	Reason string

	// Scope describes how broad the pattern is (all-sites, subdomain, single).
	Scope string
}

// Report is the full audit result for a manifest.
type Report struct {
	// Permissions is the per-permission findings list.
	Permissions []PermissionFinding

	// Hosts is the per-host-pattern findings list.
	Hosts []HostFinding

	// TotalScore is the aggregate numeric risk score (0-100).
	TotalScore int

	// Overall is the categorical overall risk level.
	Overall Level

	// Summary is a one-line human-readable summary.
	Summary string
}

// Audit evaluates the given permissions and host patterns. Either slice may be
// nil/empty. Permissions are matched case-sensitively against the built-in
// catalog; unknown permissions are reported at Low risk.
func Audit(permissions, hostPatterns []string) Report {
	var (
		findings []PermissionFinding
		hostFind []HostFinding
	)

	for _, p := range dedupSorted(permissions) {
		findings = append(findings, assessPermission(p))
	}
	for _, h := range dedupSorted(hostPatterns) {
		hostFind = append(hostFind, assessHost(h))
	}

	total := aggregateScore(findings, hostFind)
	overall := scoreToLevel(total)

	report := Report{
		Permissions: findings,
		Hosts:       hostFind,
		TotalScore:  total,
		Overall:     overall,
	}
	report.Summary = BuildSummary(report)
	return report
}

// assessPermission maps a single permission to a finding via the built-in catalog.
func assessPermission(p string) PermissionFinding {
	if f, ok := catalog[p]; ok {
		return f
	}
	// Unknown permissions: assume low risk but flag for review.
	return PermissionFinding{
		Permission: p,
		Level:      LevelLow,
		Score:      10,
		Reason:     "Unknown permission; review the documentation for its capabilities.",
		Category:   "Unknown",
	}
}

// assessHost evaluates a single host match pattern's breadth of access.
func assessHost(pattern string) HostFinding {
	p := strings.ToLower(strings.TrimSpace(pattern))
	scope := "single-site"
	reason := "Access limited to a single site."

	switch {
	case p == "<all_urls>" || p == "*" || p == "*://*/*" || strings.Contains(p, "://*/*"):
		return HostFinding{
			Pattern: pattern, Level: LevelCritical, Score: 90, Scope: "all-sites",
			Reason: "Requests access to every site you visit. This is the broadest possible host access.",
		}
	case strings.HasPrefix(p, "*://"):
		return HostFinding{
			Pattern: pattern, Level: LevelHigh, Score: 60, Scope: "all-schemes",
			Reason: "Matches both http and https schemes on the declared hosts.",
		}
	case strings.Contains(p, "://*.") || strings.HasPrefix(p, "*."):
		scope = "subdomain"
		reason = "Matches any subdomain of the declared domain."
	case strings.Contains(p, "*") && !strings.Contains(p, "://"):
		scope = "wildcard-path"
		reason = "Contains a wildcard path component; review the host portion."
	}

	level := LevelLow
	score := 15
	switch scope {
	case "subdomain":
		level = LevelModerate
		score = 35
	case "wildcard-path":
		level = LevelModerate
		score = 30
	}

	return HostFinding{
		Pattern: pattern,
		Level:   level,
		Score:   score,
		Reason:  reason,
		Scope:   scope,
	}
}

// aggregateScore combines permission and host scores into a 0-100 total. The
// overall level is driven primarily by the single most dangerous finding, with
// a breadth escalator added when many permissions or broad host access stack
// up. This keeps the categorical verdict explainable: one Critical capability
// yields a Critical manifest, but a pile of Moderate permissions can escalate.
func aggregateScore(perms []PermissionFinding, hosts []HostFinding) int {
	maxScore := 0
	highCount := 0
	criticalCount := 0
	for _, f := range perms {
		if f.Score > maxScore {
			maxScore = f.Score
		}
		switch f.Level {
		case LevelHigh:
			highCount++
		case LevelCritical:
			criticalCount++
		}
	}
	for _, h := range hosts {
		if h.Score > maxScore {
			maxScore = h.Score
		}
		switch h.Level {
		case LevelHigh:
			highCount++
		case LevelCritical:
			criticalCount++
		}
	}

	total := maxScore

	// Breadth escalator: each additional High finding adds 5, each additional
	// Critical finding adds 10, capped so the escalator cannot push a Low-only
	// manifest into Critical on volume alone.
	escalator := (highCount-1)*5 + (criticalCount-1)*10
	if highCount == 0 && criticalCount == 0 {
		escalator = 0
	}
	if escalator < 0 {
		escalator = 0
	}
	total += escalator
	if total > 100 {
		total = 100
	}
	return total
}

func scoreToLevel(score int) Level {
	switch {
	case score >= 80:
		return LevelCritical
	case score >= 60:
		return LevelHigh
	case score >= 35:
		return LevelModerate
	case score >= 10:
		return LevelLow
	default:
		return LevelNone
	}
}

// BuildSummary produces a one-line human summary. (Kept as a separate exported
// helper so callers can re-render after localizing.)
func BuildSummary(r Report) string {
	if len(r.Permissions) == 0 && len(r.Hosts) == 0 {
		return "No permissions or host access declared."
	}
	var criticals, highs int
	for _, f := range r.Permissions {
		if f.Level == LevelCritical {
			criticals++
		}
		if f.Level == LevelHigh {
			highs++
		}
	}
	for _, h := range r.Hosts {
		if h.Level == LevelCritical {
			criticals++
		}
		if h.Level == LevelHigh {
			highs++
		}
	}
	switch {
	case criticals > 0:
		return "High-risk access detected: requests broad or sensitive capabilities. Review carefully before installing."
	case highs > 0:
		return "Notable access detected: requests sensitive permissions. Confirm they match the extension's purpose."
	case r.Overall == LevelModerate:
		return "Moderate access: routine permissions with some data or site reach."
	default:
		return "Low access: permissions appear minimal and routine."
	}
}

func dedupSorted(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// catalog is the built-in permission risk catalog. Scores are 0-100.
var catalog = map[string]PermissionFinding{
	"storage": {
		Permission: "storage", Level: LevelLow, Score: 10, Category: "LocalData",
		Reason: "Stores data locally in the browser; no network or site access implied.",
	},
	"alarms": {
		Permission: "alarms", Level: LevelLow, Score: 5, Category: "Scheduling",
		Reason: "Schedules timed code execution; no direct data access.",
	},
	"contextMenus": {
		Permission: "contextMenus", Level: LevelLow, Score: 10, Category: "UI",
		Reason: "Adds items to the right-click menu.",
	},
	"notifications": {
		Permission: "notifications", Level: LevelLow, Score: 15, Category: "UI",
		Reason: "Shows desktop notifications; can be abused for phishing but has no data access.",
	},
	"clipboardWrite": {
		Permission: "clipboardWrite", Level: LevelLow, Score: 15, Category: "Clipboard",
		Reason: "Can write to the clipboard.",
	},
	"clipboardRead": {
		Permission: "clipboardRead", Level: LevelModerate, Score: 40, Category: "Clipboard",
		Reason: "Can read anything you copy, including passwords or secrets.",
	},
	"activeTab": {
		Permission: "activeTab", Level: LevelLow, Score: 20, Category: "Privacy",
		Reason: "Access to the current tab only when the user invokes the extension.",
	},
	"tabs": {
		Permission: "tabs", Level: LevelModerate, Score: 45, Category: "Privacy",
		Reason: "Reads the URL and title of every open tab.",
	},
	"tabGroups": {
		Permission: "tabGroups", Level: LevelLow, Score: 15, Category: "Tabs",
		Reason: "Manages tab groupings; no content access.",
	},
	"webRequest": {
		Permission: "webRequest", Level: LevelHigh, Score: 70, Category: "Network",
		Reason: "Observes and can modify or block network requests from any permitted host.",
	},
	"webRequestBlocking": {
		Permission: "webRequestBlocking", Level: LevelHigh, Score: 80, Category: "Network",
		Reason: "Synchronously blocks and rewrites network traffic (MV2 only).",
	},
	"declarativeNetRequest": {
		Permission: "declarativeNetRequest", Level: LevelModerate, Score: 45, Category: "Network",
		Reason: "Declares static rules to modify or block network requests.",
	},
	"cookies": {
		Permission: "cookies", Level: LevelHigh, Score: 65, Category: "Privacy",
		Reason: "Reads and modifies cookies for permitted hosts (often includes session tokens).",
	},
	"history": {
		Permission: "history", Level: LevelHigh, Score: 60, Category: "Privacy",
		Reason: "Reads and modifies your full browsing history.",
	},
	"bookmarks": {
		Permission: "bookmarks", Level: LevelModerate, Score: 35, Category: "DataAccess",
		Reason: "Reads and modifies your bookmarks.",
	},
	"downloads": {
		Permission: "downloads", Level: LevelModerate, Score: 40, Category: "DataAccess",
		Reason: "Initiates downloads and reads the download list.",
	},
	"management": {
		Permission: "management", Level: LevelHigh, Score: 60, Category: "System",
		Reason: "Can disable or uninstall other extensions.",
	},
	"nativeMessaging": {
		Permission: "nativeMessaging", Level: LevelCritical, Score: 85, Category: "System",
		Reason: "Communicates with a native application installed on your computer, escaping the browser sandbox.",
	},
	"nativeMessagingHost": {
		Permission: "nativeMessagingHost", Level: LevelCritical, Score: 85, Category: "System",
		Reason: "Registers or replaces a native messaging host (arbitrary code execution surface).",
	},
	"system.cpu": {
		Permission: "system.cpu", Level: LevelLow, Score: 10, Category: "System",
		Reason: "Reads CPU metadata.",
	},
	"system.memory": {
		Permission: "system.memory", Level: LevelLow, Score: 15, Category: "System",
		Reason: "Reads memory metadata.",
	},
	"system.storage": {
		Permission: "system.storage", Level: LevelLow, Score: 15, Category: "System",
		Reason: "Reads attached storage device metadata.",
	},
	"system.display": {
		Permission: "system.display", Level: LevelLow, Score: 15, Category: "System",
		Reason: "Reads display metadata.",
	},
	"geolocation": {
		Permission: "geolocation", Level: LevelHigh, Score: 65, Category: "Privacy",
		Reason: "Accesses your physical location.",
	},
	"identity": {
		Permission: "identity", Level: LevelModerate, Score: 40, Category: "Identity",
		Reason: "Obtains an OAuth token tied to your Google account.",
	},
	"identity.email": {
		Permission: "identity.email", Level: LevelHigh, Score: 55, Category: "Identity",
		Reason: "Reads the signed-in account's email address.",
	},
	"proxy": {
		Permission: "proxy", Level: LevelHigh, Score: 65, Category: "Network",
		Reason: "Controls browser proxy settings; can redirect all traffic.",
	},
	"privacy": {
		Permission: "privacy", Level: LevelHigh, Score: 55, Category: "Privacy",
		Reason: "Changes privacy-related browser settings.",
	},
	"tts": {
		Permission: "tts", Level: LevelLow, Score: 10, Category: "Media",
		Reason: "Uses text-to-speech output.",
	},
	"usb": {
		Permission: "usb", Level: LevelHigh, Score: 65, Category: "Hardware",
		Reason: "Communicates directly with USB devices.",
	},
	"bluetooth": {
		Permission: "bluetooth", Level: LevelModerate, Score: 40, Category: "Hardware",
		Reason: "Discovers and interacts with Bluetooth devices.",
	},
	"serial": {
		Permission: "serial", Level: LevelHigh, Score: 60, Category: "Hardware",
		Reason: "Reads/writes serial ports.",
	},
	"fileBrowserHandler": {
		Permission: "fileBrowserHandler", Level: LevelModerate, Score: 40, Category: "DataAccess",
		Reason: "Registers as a handler for file selection (ChromeOS).",
	},
	"pageCapture": {
		Permission: "pageCapture", Level: LevelModerate, Score: 40, Category: "Privacy",
		Reason: "Saves the current page as MHTML (full content snapshot).",
	},
	"topSites": {
		Permission: "topSites", Level: LevelModerate, Score: 35, Category: "Privacy",
		Reason: "Reads your most-visited sites.",
	},
}
