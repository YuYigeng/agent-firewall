package redact

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/YuYigeng/agent-firewall/internal/action"
)

var (
	sensitiveKey = regexp.MustCompile(`(?i)(token|secret|password|passwd|api[_-]?key|authorization|cookie|private[_-]?key|credential)`)
	patterns     = []struct {
		category string
		re       *regexp.Regexp
	}{
		{"aws-access-key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
		{"github-token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{20,}`)},
		{"bearer-token", regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}`)},
		{"api-key", regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{16,}`)},
		{"assigned-secret", regexp.MustCompile(`(?i)((?:token|secret|password|passwd|api[_-]?key)["']?\s*[:=]\s*["']?)[A-Za-z0-9._~+/=-]{8,}`)},
	}
)

type Report map[string]int

func Action(input action.Action) (action.Action, Report) {
	report := Report{}
	output := input
	if output.SessionID != "" {
		sum := sha256.Sum256([]byte(output.SessionID))
		output.SessionID = "sha256:" + hex.EncodeToString(sum[:8])
	}
	redacted, _ := Value(output.Attributes, report).(map[string]any)
	output.Attributes = redacted
	output.Subject = String(output.Subject, report)
	return output, report
}

func Value(input any, report Report) any {
	switch value := input.(type) {
	case map[string]any:
		output := make(map[string]any, len(value))
		for key, item := range value {
			if sensitiveKey.MatchString(key) {
				report["sensitive-field"]++
				output[key] = "<redacted:sensitive-field>"
				continue
			}
			output[key] = Value(item, report)
		}
		return output
	case []any:
		output := make([]any, len(value))
		for index, item := range value {
			output[index] = Value(item, report)
		}
		return output
	case []string:
		output := make([]string, len(value))
		for index, item := range value {
			output[index] = String(item, report)
		}
		return output
	case string:
		return String(value, report)
	default:
		return input
	}
}

func String(input string, report Report) string {
	output := input
	for _, pattern := range patterns {
		before := output
		if pattern.category == "assigned-secret" {
			output = pattern.re.ReplaceAllString(output, `${1}<redacted:assigned-secret>`)
		} else {
			output = pattern.re.ReplaceAllString(output, "<redacted:"+pattern.category+">")
		}
		if before != output {
			report[pattern.category]++
		}
	}
	return output
}

func SafeReason(ruleID, reason string) string {
	report := Report{}
	clean := strings.TrimSpace(String(reason, report))
	if clean == "" {
		clean = fmt.Sprintf("Decision from policy rule %s", ruleID)
	}
	return clean
}
