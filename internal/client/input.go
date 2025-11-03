package client

import "strings"

func (a *App) handleTabCompletion() bool {
	value := a.input.Value()
	if value == "" {
		return true
	}

	cursor := a.input.Position()
	runes := []rune(value)
	if cursor != len(runes) {
		return true
	}

	segment := string(runes)
	if !strings.HasPrefix(segment, string(a.cfg.CommandPrefix)) {
		return true
	}
	if strings.Contains(segment, " ") || strings.Contains(segment, "\t") {
		return true
	}

	matches := make([]string, 0)
	for _, cmd := range a.commands {
		if strings.HasPrefix(cmd.trigger, segment) {
			matches = append(matches, cmd.trigger)
		}
	}
	if len(matches) == 0 {
		return true
	}

	prefix := longestCommonPrefix(matches)
	if len(prefix) <= len(segment) {
		return true
	}

	a.input.SetValue(prefix)
	a.input.CursorEnd()
	return true
}

func longestCommonPrefix(values []string) string {
	if len(values) == 0 {
		return ""
	}
	prefix := values[0]
	for _, s := range values[1:] {
		for !strings.HasPrefix(s, prefix) {
			if prefix == "" {
				return ""
			}
			prefix = prefix[:len(prefix)-1]
		}
	}
	return prefix
}
