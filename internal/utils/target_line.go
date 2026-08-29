package utils

import "strings"

// ParseTargetLine applies the lexical target-stream rules shared by scope
// construction and scanner replay. Target interpretation remains the
// responsibility of StreamTargets.
func ParseTargetLine(line string) (string, bool) {
	target := strings.TrimSpace(line)
	if target == "" || strings.HasPrefix(target, "#") {
		return "", false
	}
	return target, true
}
