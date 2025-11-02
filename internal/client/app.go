package client

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/uuid"

	"github.com/fenggwsx/SlashChat/internal/config"
	"github.com/fenggwsx/SlashChat/internal/protocol"
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

	session *Session

	logLine logMessage

	statusOnline bool
	authToken    string
	username     string
	room         string

	chatHistory []string
	commands    []commandSpec

	showHelp   bool
	helpView   string
	helpHeight int

	serverAddr string

	pendingRequests map[string]pendingRequest
	lastAuthAction  string
	lastAuthUser    string

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

type pendingRequest struct {
	action   string
	username string
}

type connectResultMsg struct {
	session *Session
	address string
	err     error
}

type sessionEnvelopeMsg struct {
	session  *Session
	envelope protocol.Envelope
}

type sessionClosedMsg struct {
	session *Session
}

type sendResultMsg struct {
	session     *Session
	id          string
	description string
	err         error
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

		chatHistory:     []string{},
		commands:        defaultCommands(),
		pendingRequests: make(map[string]pendingRequest),

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
				if submitCmd := a.handleSubmit(value); submitCmd != nil {
					cmds = append(cmds, submitCmd)
				}
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

		if len(cmds) == 0 {
			return a, nil
		}
		return a, tea.Batch(cmds...)

	case connectResultMsg:
		if m.session != a.session {
			return a, nil
		}
		if m.err != nil {
			a.statusOnline = false
			a.authToken = ""
			a.logf("Failed to connect to %s: %v", m.address, m.err)
			_ = a.session.Close()
			a.session = nil
			return a, nil
		}
		a.statusOnline = true
		a.cfg.ServerAddr = m.address
		a.logf("Connected to %s", m.address)
		return a, a.listenForSession()

	case sessionEnvelopeMsg:
		if m.session != a.session {
			return a, nil
		}
		a.handleSessionEnvelope(m.envelope)
		return a, a.listenForSession()

	case sessionClosedMsg:
		if m.session != a.session {
			return a, nil
		}
		a.statusOnline = false
		a.authToken = ""
		a.logf("Disconnected from %s", a.serverAddr)
		a.appendSystemMessage("Disconnected from server")
		a.session = nil
		return a, nil

	case sendResultMsg:
		if m.session != a.session {
			return a, nil
		}
		if m.err != nil {
			if _, ok := a.pendingRequests[m.id]; ok {
				delete(a.pendingRequests, m.id)
			}
			a.logf("%s failed: %v", m.description, m.err)
		}
		return a, nil

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

func (a *App) handleSubmit(value string) tea.Cmd {
	if strings.HasPrefix(value, string(a.cfg.CommandPrefix)) {
		return a.executeCommand(value)
	}

	a.appendChatMessage(value)
	return nil
}

func (a *App) executeCommand(raw string) tea.Cmd {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return nil
	}

	cmd := fields[0]
	var cmds []tea.Cmd

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
		if target == "" {
			a.logf("Provide a server address to connect")
			break
		}
		if connectCmd := a.connectToServer(target); connectCmd != nil {
			cmds = append(cmds, connectCmd)
		}
	case "/register":
		if len(fields) < 3 {
			a.logf("Usage: /register <username> <password>")
			break
		}
		if !a.isConnected() {
			a.logf("Not connected. Use /connect first.")
			break
		}
		username := fields[1]
		password := strings.Join(fields[2:], " ")
		if strings.TrimSpace(password) == "" {
			a.logf("Password cannot be empty")
			break
		}
		a.logf("Registering %s ...", username)
		if authCmd := a.sendAuthCommand("register", username, password); authCmd != nil {
			cmds = append(cmds, authCmd)
		}
	case "/login":
		if len(fields) < 3 {
			a.logf("Usage: /login <username> <password>")
			break
		}
		if !a.isConnected() {
			a.logf("Not connected. Use /connect first.")
			break
		}
		username := fields[1]
		password := strings.Join(fields[2:], " ")
		if strings.TrimSpace(password) == "" {
			a.logf("Password cannot be empty")
			break
		}
		a.logf("Logging in as %s ...", username)
		if authCmd := a.sendAuthCommand("login", username, password); authCmd != nil {
			cmds = append(cmds, authCmd)
		}
	case "/quit":
		a.logf("Exiting client")
		a.appendSystemMessage("Session ended. Press Ctrl+C to close.")
		if a.session != nil {
			_ = a.session.Close()
			a.session = nil
		}
		a.statusOnline = false
		a.authToken = ""
		cmds = append(cmds, tea.Quit)
	default:
		a.logf("Command %s not implemented", cmd)
	}

	a.updateViewportContent()

	switch len(cmds) {
	case 0:
		return nil
	case 1:
		return cmds[0]
	default:
		return tea.Batch(cmds...)
	}
}

func (a *App) connectToServer(target string) tea.Cmd {
	if target == "" {
		return nil
	}
	if a.session != nil {
		_ = a.session.Close()
	}

	cfg := a.cfg
	cfg.ServerAddr = target
	session := NewSession(cfg)
	a.session = session
	a.serverAddr = target
	a.statusOnline = false
	a.authToken = ""
	a.pendingRequests = make(map[string]pendingRequest)
	a.lastAuthAction = ""
	a.lastAuthUser = ""
	a.logf("Connecting to %s ...", target)

	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := session.Connect(ctx)
		return connectResultMsg{
			session: session,
			address: target,
			err:     err,
		}
	}
}

func (a *App) listenForSession() tea.Cmd {
	session := a.session
	if session == nil {
		return nil
	}
	return func() tea.Msg {
		env, ok := <-session.Messages()
		if !ok {
			return sessionClosedMsg{session: session}
		}
		return sessionEnvelopeMsg{session: session, envelope: env}
	}
}

func (a *App) sendAuthCommand(action, username, password string) tea.Cmd {
	session := a.session
	if session == nil {
		return nil
	}
	if a.pendingRequests == nil {
		a.pendingRequests = make(map[string]pendingRequest)
	}
	requestID := uuid.NewString()
	a.pendingRequests[requestID] = pendingRequest{action: action, username: username}

	env := protocol.Envelope{
		ID:   requestID,
		Type: protocol.MessageTypeAuthRequest,
		Payload: protocol.AuthRequest{
			Action:   action,
			Username: username,
			Password: password,
		},
	}

	return a.sendEnvelope(session, env, fmt.Sprintf("%s request", action), false)
}

func (a *App) sendEnvelope(session *Session, env protocol.Envelope, description string, attachToken bool) tea.Cmd {
	if env.ID == "" {
		env.ID = uuid.NewString()
	}
	envCopy := env
	token := a.authToken
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if attachToken && envCopy.Token == "" && token != "" {
			envCopy.Token = token
		}
		err := session.Send(ctx, envCopy)
		return sendResultMsg{
			session:     session,
			id:          envCopy.ID,
			description: description,
			err:         err,
		}
	}
}

func (a *App) handleSessionEnvelope(env protocol.Envelope) {
	switch env.Type {
	case protocol.MessageTypeAck:
		a.handleAckEnvelope(env)
	case protocol.MessageTypeAuthResponse:
		a.handleAuthResponse(env)
	default:
		a.logf("Received %s message", string(env.Type))
	}
}

func (a *App) handleAckEnvelope(env protocol.Envelope) {
	ack, err := decodeAckPayload(env.Payload)
	if err != nil {
		a.logf("Failed to decode ack: %v", err)
		return
	}

	pending, ok := a.pendingRequests[ack.ReferenceID]
	if !ok {
		if ack.Reason != "" {
			a.logf("Server response: %s", ack.Reason)
		}
		return
	}
	delete(a.pendingRequests, ack.ReferenceID)

	statusOK := strings.EqualFold(ack.Status, "ok")
	action := strings.ToLower(pending.action)

	if statusOK {
		switch action {
		case "register":
			a.logf("Registration accepted for %s", pending.username)
		case "login":
			a.logf("Login accepted for %s", pending.username)
		default:
			a.logf("Command %s acknowledged", pending.action)
		}
		if action == "register" || action == "login" {
			a.lastAuthAction = pending.action
			a.lastAuthUser = pending.username
		}
		return
	}

	reason := ack.Reason
	if strings.TrimSpace(reason) == "" {
		reason = "unknown error"
	}
	switch action {
	case "register":
		a.logf("Registration failed: %s", reason)
	case "login":
		a.logf("Login failed: %s", reason)
	default:
		a.logf("Command %s failed: %s", pending.action, reason)
	}
	if action == "register" || action == "login" {
		a.lastAuthAction = ""
		a.lastAuthUser = ""
	}
}

func (a *App) handleAuthResponse(env protocol.Envelope) {
	resp, err := decodeAuthResponse(env.Payload)
	if err != nil {
		a.logf("Failed to decode auth response: %v", err)
		return
	}

	if a.lastAuthUser != "" {
		a.username = a.lastAuthUser
	}
	a.authToken = resp.Token

	message := fmt.Sprintf("Authenticated as %s", a.username)
	if resp.ExpiresAt != 0 {
		expiresAt := time.Unix(resp.ExpiresAt, 0).UTC().Format(time.RFC3339)
		message = fmt.Sprintf("%s (token expires %s)", message, expiresAt)
	}

	a.logf(message)
	a.appendSystemMessage(message)
	a.lastAuthAction = ""
	a.lastAuthUser = ""
}

func (a *App) isConnected() bool {
	return a.session != nil && a.statusOnline
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
		{trigger: "/register", usage: "/register <username> <password>", description: "Register a new account"},
		{trigger: "/login", usage: "/login <username> <password>", description: "Authenticate with existing credentials"},
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

const homeContent = "SlashChat\n\nUse /connect to reach the server.\nUse /register or /login after connecting.\nUse /help to browse all commands."

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

func decodeAckPayload(payload interface{}) (protocol.AckPayload, error) {
	var ack protocol.AckPayload
	if payload == nil {
		return ack, fmt.Errorf("ack payload empty")
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return ack, err
	}
	if err := json.Unmarshal(data, &ack); err != nil {
		return ack, err
	}
	return ack, nil
}

func decodeAuthResponse(payload interface{}) (protocol.AuthResponse, error) {
	var resp protocol.AuthResponse
	if payload == nil {
		return resp, fmt.Errorf("auth response payload empty")
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return resp, err
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return resp, err
	}
	return resp, nil
}
