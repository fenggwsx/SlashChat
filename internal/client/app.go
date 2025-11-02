package client

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/fenggwsx/SlashChat/internal/config"
)

type activeView int

const (
	viewHome activeView = iota
	viewChat
	viewHelp
)

// App encapsulates the Bubble Tea TUI state for the GoSlash client.
type App struct {
	cfg config.ClientConfig

	view activeView

	width  int
	height int

	viewport viewport.Model
	input    textinput.Model
	helper   help.Model

	logLine logMessage

	statusOnline bool
	username     string
	room         string

	chatHistory []string
	commands    []commandSpec

	showHelp   bool
	helpView   string
	helpHeight int

	serverAddr string

	styles styleSet
}

type commandSpec struct {
	trigger     string
	usage       string
	description string
}

type logMessage struct {
	label string
	body  string
}

type styleSet struct {
	title         lipgloss.Style
	view          lipgloss.Style
	statusOnline  lipgloss.Style
	statusOffline lipgloss.Style
	label         lipgloss.Style
	value         lipgloss.Style
	logLabel      lipgloss.Style
	logBody       lipgloss.Style
	help          lipgloss.Style
}

// NewApp constructs the client application model.
func NewApp(cfg config.ClientConfig) *App {
	input := textinput.New()
	input.Prompt = "> "
	input.Placeholder = "Type a message or start with / for commands"
	input.CharLimit = 256
	input.Width = 60
	input.Focus()

	vp := viewport.New(0, 0)
	vp.MouseWheelEnabled = true
	helper := help.New()
	helper.ShowAll = true

	app := &App{
		cfg:        cfg,
		view:       viewHome,
		serverAddr: cfg.ServerAddr,

		viewport: vp,
		input:    input,
		helper:   helper,

		logLine: logMessage{label: "[msg]", body: "GoSlash client ready"},

		statusOnline: false,
		username:     "guest",
		room:         "-",

		chatHistory: []string{},
		commands:    defaultCommands(),

		styles: buildStyles(),
	}

	app.updateInputWidth()
	app.updateViewportContent()
	app.updateHelp()

	return app
}

// Init satisfies tea.Model.
func (a *App) Init() tea.Cmd {
	return textinput.Blink
}

// Update drives the Bubble Tea update loop.
func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m := msg.(type) {
	case tea.WindowSizeMsg:
		a.width = m.Width
		a.height = m.Height
		a.viewport.Width = a.width
		a.updateInputWidth()
		a.updateHelp()
		a.updateViewportSize()
		a.updateViewportContent()
		return a, nil

	case tea.KeyMsg:
		if m.Type == tea.KeyCtrlC {
			return a, tea.Quit
		}

		if !a.input.Focused() {
			a.input.Focus()
		}

		var cmds []tea.Cmd
		var cmd tea.Cmd

		a.input, cmd = a.input.Update(m)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}

		if m.Type == tea.KeyEnter {
			value := strings.TrimSpace(a.input.Value())
			if value != "" {
				a.handleSubmit(value)
			}
			a.input.SetValue("")
			a.input.CursorEnd()
		}

		a.updateHelp()
		a.updateViewportSize()

		a.viewport, cmd = a.viewport.Update(m)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}

		return a, tea.Batch(cmds...)

	case tea.MouseMsg:
		var cmd tea.Cmd
		a.viewport, cmd = a.viewport.Update(m)
		return a, cmd
	}

	var cmd tea.Cmd
	a.viewport, cmd = a.viewport.Update(msg)
	return a, cmd
}

// View renders the composed layout.
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

func (a *App) handleSubmit(value string) {
	if strings.HasPrefix(value, string(a.cfg.CommandPrefix)) {
		a.executeCommand(value)
		return
	}

	a.appendChatMessage(value)
}

func (a *App) executeCommand(raw string) {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return
	}

	cmd := fields[0]
	switch cmd {
	case "/home":
		a.view = viewHome
		a.logf("Switched to HOME view")
	case "/chat":
		a.view = viewChat
		a.logf("Switched to CHAT view")
	case "/help":
		a.view = viewHelp
		a.logf("Switched to HELP view")
	case "/connect":
		target := a.serverAddr
		if len(fields) > 1 {
			target = fields[1]
		}
		a.serverAddr = target
		a.statusOnline = true
		a.logf("Connecting to %s (stub)", target)
	case "/quit":
		a.logf("Exiting client")
		a.appendSystemMessage("Session ended. Press Ctrl+C to close.")
		return
	default:
		a.logf("Command %s not implemented", cmd)
	}

	a.updateViewportContent()
}

func (a *App) appendSystemMessage(text string) {
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}
	message := fmt.Sprintf("[system] %s", text)
	a.chatHistory = append(a.chatHistory, message)
	if a.view == viewChat {
		a.updateViewportContent()
		a.viewport.GotoBottom()
	}
}

func (a *App) appendChatMessage(text string) {
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}

	message := fmt.Sprintf("%s: %s", a.username, text)
	a.chatHistory = append(a.chatHistory, message)
	a.logf("Appended message to chat view")

	if a.view == viewChat {
		a.updateViewportContent()
		a.viewport.GotoBottom()
	}
}

func (a *App) updateViewportContent() {
	switch a.view {
	case viewHome:
		a.viewport.SetContent(homeContent)
	case viewChat:
		if len(a.chatHistory) == 0 {
			a.viewport.SetContent("No chat messages yet. Type and press Enter to send.")
		} else {
			a.viewport.SetContent(strings.Join(a.chatHistory, "\n"))
		}
		a.viewport.GotoBottom()
	case viewHelp:
		a.viewport.SetContent(a.renderHelpView())
	}
}

func (a *App) updateViewportSize() {
	if a.height == 0 {
		return
	}
	const fixed = 3 // input + log + status
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
		a.styles.title.Render("GoSlash"),
		a.styles.view.Render(strings.ToUpper(a.view.String())),
		a.statusValueStyle(status).Render(status),
		a.styles.label.Render("Server") + ": " + a.styles.value.Render(a.serverAddr),
		a.styles.label.Render("User") + ": " + a.styles.value.Render(a.username),
		a.styles.label.Render("Room") + ": " + a.styles.value.Render(a.room),
	}

	return strings.Join(parts, " | ")
}

func (a *App) logf(format string, args ...any) {
	a.logLine = logMessage{
		label: "[msg]",
		body:  fmt.Sprintf(format, args...),
	}
}

func defaultCommands() []commandSpec {
	return []commandSpec{
		{trigger: "/connect", usage: "/connect [addr]", description: "Connect to the server"},
		{trigger: "/home", usage: "/home", description: "Switch to home view"},
		{trigger: "/chat", usage: "/chat", description: "Switch to chat view"},
		{trigger: "/help", usage: "/help", description: "Show command help"},
		{trigger: "/join", usage: "/join <room>", description: "Join a room"},
		{trigger: "/leave", usage: "/leave", description: "Leave current room"},
		{trigger: "/upload", usage: "/upload <path>", description: "Upload a file"},
		{trigger: "/download", usage: "/download <file>", description: "Download a file"},
		{trigger: "/quit", usage: "/quit", description: "Exit the client"},
	}
}

func (v activeView) String() string {
	switch v {
	case viewHome:
		return "home"
	case viewChat:
		return "chat"
	case viewHelp:
		return "help"
	default:
		return "unknown"
	}
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

const homeContent = "SlashChat\n\nUse /connect to reach the server.\nUse /help to browse all commands."

func (a *App) renderHelpView() string {
	var b strings.Builder
	b.WriteString("SlashChat Commands\n\n")
	for _, c := range a.commands {
		b.WriteString(fmt.Sprintf("%-18s %s\n", c.usage, c.description))
	}
	return strings.TrimRight(b.String(), "\n")
}

func buildStyles() styleSet {
	base := lipgloss.NewStyle()
	return styleSet{
		title:         base.Foreground(lipgloss.Color("#7D56F9")).Bold(true),
		view:          base.Foreground(lipgloss.Color("#39B5E0")).Bold(true),
		statusOnline:  base.Foreground(lipgloss.Color("#31C48D")).Bold(true),
		statusOffline: base.Foreground(lipgloss.Color("#F87373")).Bold(true),
		label:         base.Foreground(lipgloss.Color("#9399B2")),
		value:         base.Foreground(lipgloss.Color("#E5E7EB")),
		logLabel:      base.Foreground(lipgloss.Color("#C792EA")).Bold(true),
		logBody:       base.Foreground(lipgloss.Color("#DADFE1")),
		help:          base.Foreground(lipgloss.Color("#94A3B8")),
	}
}

func (a *App) statusValueStyle(status string) lipgloss.Style {
	if strings.EqualFold(status, "ONLINE") {
		return a.styles.statusOnline
	}
	return a.styles.statusOffline
}

func (a *App) logLineView() string {
	return a.styles.logLabel.Render(a.logLine.label) + " " + a.styles.logBody.Render(a.logLine.body)
}
