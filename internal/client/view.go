package client

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/lipgloss"
	figure "github.com/common-nighthawk/go-figure"
	"github.com/mattn/go-runewidth"
)

var homeContent = buildHomeContent()

func (a *App) View() string {
	var b strings.Builder

	b.WriteString(a.viewport.View())
	b.WriteString("\n")

	if a.showHelp && a.helpView != "" {
		b.WriteString(a.styles.help.Render(a.helpView))
		b.WriteString("\n")
	}

	b.WriteString(a.input.View())
	b.WriteString("\n")
	b.WriteString(a.logLineView())
	b.WriteString("\n")
	b.WriteString(a.statusLine())

	return b.String()
}

func (a *App) updateViewportContent() {
	switch a.view {
	case viewChat:
		if !a.hasActiveRoom() {
			a.viewport.SetContent(homeContent)
			return
		}
		width := a.viewport.Width
		if width <= 0 {
			width = a.width
		}
		if len(a.chatHistory) == 0 {
			a.viewport.SetContent("No chat messages yet. Type and press Enter to send.")
		} else {
			lines := wrapLines(a.chatHistory, width)
			a.viewport.SetContent(strings.Join(lines, "\n"))
		}
		a.viewport.GotoBottom()
	case viewPipe:
		width := a.viewport.Width
		if width <= 0 {
			width = a.width
		}
		if len(a.pipeHistory) == 0 {
			a.viewport.SetContent("No transport frames captured yet. Send commands to populate this view or use /pipe clear to reset.")
		} else {
			a.viewport.SetContent(a.renderPipeView())
		}
		a.viewport.GotoBottom()
	case viewHelp:
		a.viewport.SetContent(a.renderHelpView())
	}
}

func (a *App) hasActiveRoom() bool {
	room := strings.TrimSpace(a.room)
	return room != "" && room != "-"
}

func (a *App) updateViewportSize() {
	if a.height == 0 {
		return
	}
	const fixed = 3
	height := a.height - fixed - a.helpHeight
	if height < 3 {
		height = 3
	}
	a.viewport.Height = height
	a.viewport.Width = a.width
}

func (a *App) updateInputWidth() {
	width := a.width
	if width <= 0 {
		width = 60
	}
	promptWidth := lipgloss.Width(a.input.Prompt)
	usable := width - promptWidth - 1
	if usable < 10 {
		usable = 10
	}
	a.input.Width = usable
}

func (a *App) updateHelp() {
	value := a.input.Value()
	if value == "" || !strings.HasPrefix(value, string(a.cfg.CommandPrefix)) {
		a.showHelp = false
		a.helpView = ""
		a.helpHeight = 0
		return
	}

	token := value
	if idx := strings.IndexAny(value, " \t"); idx >= 0 {
		token = value[:idx]
	}

	bindings := a.matchingBindings(token)
	if len(bindings) == 0 {
		a.showHelp = false
		a.helpView = ""
		a.helpHeight = 0
		return
	}

	a.showHelp = true
	a.helper.Width = a.width
	view := a.helper.View(dynamicKeyMap{keys: bindings})
	view = strings.TrimRight(view, "\n")
	a.helpView = view
	a.helpHeight = countLines(view)
}

func (a *App) matchingBindings(prefix string) []key.Binding {
	prefix = strings.ToLower(prefix)
	var bindings []key.Binding
	for _, c := range a.commands {
		if strings.HasPrefix(strings.ToLower(c.trigger), prefix) {
			bindings = append(bindings, key.NewBinding(
				key.WithKeys(c.usage),
				key.WithHelp(c.usage, c.description),
			))
		}
	}
	return bindings
}

func (a *App) statusLine() string {
	status := "OFFLINE"
	if a.statusOnline {
		status = "ONLINE"
	}

	parts := []string{
		a.styles.title.Render("SlashChat"),
		a.styles.view.Render(strings.ToUpper(a.view.String())),
		a.statusValueStyle(status).Render(status),
		a.styles.label.Render("Server") + ": " + a.styles.value.Render(a.serverAddr),
		a.styles.label.Render("User") + ": " + a.styles.value.Render(a.username),
		a.styles.label.Render("Room") + ": " + a.styles.value.Render(a.room),
	}

	return strings.Join(parts, " | ")
}

func (a *App) statusValueStyle(status string) lipgloss.Style {
	if strings.EqualFold(status, "ONLINE") {
		return a.styles.statusOnline
	}
	return a.styles.statusOffline
}

func (a *App) logLineView() string {
	labelStyle := a.styles.logLabel
	bodyStyle := a.styles.logBody
	if a.logLine.level == logLevelError {
		labelStyle = a.styles.logLabelError
		bodyStyle = a.styles.logBodyError
	}
	return labelStyle.Render(a.logLine.label) + " " + bodyStyle.Render(a.logLine.body)
}

func buildStyles() styleSet {
	base := lipgloss.NewStyle()
	return styleSet{
		title:         base.Foreground(lipgloss.Color("13")).Bold(true),
		view:          base.Foreground(lipgloss.Color("14")).Bold(true),
		statusOnline:  base.Foreground(lipgloss.Color("10")).Bold(true),
		statusOffline: base.Foreground(lipgloss.Color("9")).Bold(true),
		label:         base.Foreground(lipgloss.Color("8")),
		value:         base.Foreground(lipgloss.Color("15")),
		logLabel:      base.Foreground(lipgloss.Color("11")).Bold(true),
		logBody:       base.Foreground(lipgloss.Color("7")),
		logLabelError: base.Foreground(lipgloss.Color("9")).Bold(true),
		logBodyError:  base.Foreground(lipgloss.Color("9")),
		help:          base.Foreground(lipgloss.Color("12")),
	}
}

func (a *App) renderHelpView() string {
	var b strings.Builder
	b.WriteString("SlashChat Commands\n\n")
	for _, c := range a.commands {
		b.WriteString(fmt.Sprintf("%-18s %s\n", c.usage, c.description))
	}
	return strings.TrimRight(b.String(), "\n")
}

func (a *App) renderPipeView() string {
	if len(a.pipeHistory) == 0 {
		return ""
	}
	var b strings.Builder
	for i, entry := range a.pipeHistory {
		ts := entry.timestamp.Format("15:04:05.000")
		kind := strings.ToUpper(entry.messageType)
		if kind == "" {
			kind = "UNKNOWN"
		}
		header := fmt.Sprintf("[%s %s %s]", ts, entry.direction, kind)
		b.WriteString(a.styles.label.Render(header))
		b.WriteString("\n")
		b.WriteString(entry.body)
		if i < len(a.pipeHistory)-1 {
			b.WriteString("\n\n")
		}
	}
	return b.String()
}

func buildHomeContent() string {
	fig := figure.NewColorFigure("SLASH CHAT", "3-d", "green", true)
	art := strings.TrimRight(fig.String(), "\n")
	info := []string{
		"Use /connect to reach the server.",
		"Use /register or /login after connecting.",
		"Use /join <room> to load chat history.",
		"Use /download <message_id> to retrieve shared files.",
		"Use /pipe to inspect raw transport frames.",
		"Use /help to browse all commands.",
	}

	var b strings.Builder
	b.WriteString(art)
	b.WriteString("\n\n")
	b.WriteString(strings.Join(info, "\n"))
	return b.String()
}

func wrapLines(lines []string, width int) []string {
	if width <= 0 {
		return lines
	}
	const minWidth = 10
	if width < minWidth {
		width = minWidth
	}

	wrapped := make([]string, 0, len(lines))
	for _, line := range lines {
		segment := line
		if segment == "" {
			wrapped = append(wrapped, "")
			continue
		}
		for len(segment) > 0 {
			if runewidth.StringWidth(segment) <= width {
				wrapped = append(wrapped, segment)
				break
			}
			cut := wrapCutIndex(segment, width)
			part := strings.TrimRight(segment[:cut], " ")
			if part == "" && cut > 0 {
				part = segment[:cut]
			}
			wrapped = append(wrapped, part)
			segment = strings.TrimLeft(segment[cut:], " ")
			if segment == "" {
				break
			}
		}
	}
	return wrapped
}

func wrapCutIndex(s string, limit int) int {
	var width int
	lastSpace := -1
	for i, r := range s {
		rw := runewidth.RuneWidth(r)
		if width+rw > limit {
			if lastSpace >= 0 {
				return lastSpace + 1
			}
			if width == 0 {
				return i + 1
			}
			return i
		}
		width += rw
		if unicode.IsSpace(r) {
			lastSpace = i
		}
	}
	return len(s)
}

type dynamicKeyMap struct {
	keys []key.Binding
}

func (d dynamicKeyMap) ShortHelp() []key.Binding {
	return d.keys
}

func (d dynamicKeyMap) FullHelp() [][]key.Binding {
	if len(d.keys) == 0 {
		return [][]key.Binding{}
	}
	return [][]key.Binding{d.keys}
}

func countLines(s string) int {
	if s == "" {
		return 0
	}
	return strings.Count(s, "\n") + 1
}
