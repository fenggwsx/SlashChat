package client

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/fenggwsx/SlashChat/internal/config"
	"github.com/fenggwsx/SlashChat/internal/protocol"
)

// App implements the bubbletea tea.Model interface for the terminal client.
type App struct {
	cfg         config.ClientConfig
	mode        Mode
	command     string
	input       string
	messages    []string
	completed   []string
	session     *Session
	token       string
	userID      string
	pendingUser string
	username    string
	hints       []string
	viewport    viewport.Model
	logLine     string
}

// Mode represents the current interaction mode.
type Mode int

const (
	// ModeCommand expects slash-prefixed input.
	ModeCommand Mode = iota
	// ModeInsert allows free-form message editing.
	ModeInsert
)

// NewApp returns a Bubble Tea model pre-populated with defaults.
func NewApp(cfg config.ClientConfig) tea.Model {
	vp := viewport.New(0, 0)
	app := &App{
		cfg:      cfg,
		mode:     ModeInsert,
		messages: make([]string, 0, 128),
		viewport: vp,
	}
	app.refreshViewport()
	return app
}

// Init is part of the tea.Model interface.
func (a *App) Init() tea.Cmd {
	return nil
}

// Update handles user input and internal events.
func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m := msg.(type) {
	case tea.WindowSizeMsg:
		a.resizeViewport(m.Width, m.Height)
		return a, nil
	case tea.KeyMsg:
		return a.handleKey(m)
	case connectResultMsg:
		return a.handleConnectResult(m)
	case envelopeMsg:
		return a.handleEnvelope(m)
	case sessionClosedMsg:
		return a.handleSessionClosed(m)
	case authSendResultMsg:
		return a.handleAuthResult(m)
	}
	return a, nil
}

func (a *App) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyPgUp:
		a.scrollMessages(a.viewport.Height)
		return a, nil
	case tea.KeyPgDown:
		a.scrollMessages(-a.viewport.Height)
		return a, nil
	case tea.KeyUp:
		a.scrollMessages(1)
		return a, nil
	case tea.KeyDown:
		a.scrollMessages(-1)
		return a, nil
	case tea.KeyEsc:
		a.mode = ModeInsert
		a.command = ""
		a.hints = nil
	case tea.KeyEnter:
		return a.handleEnter()
	case tea.KeyBackspace:
		a.backspace()
	default:
		a.captureInput(msg.String())
	}
	return a, nil
}

func (a *App) captureInput(value string) {
	if value == "" {
		return
	}
	if a.mode == ModeCommand {
		prefix := string(a.cfg.CommandPrefix)
		if len(a.command) == 0 {
			if value != prefix {
				return
			}
			a.command = value
			a.updateHints()
			return
		}
		a.command += value
		a.updateHints()
		return
	}
	prefix := string(a.cfg.CommandPrefix)
	if len(a.input) == 0 && value == prefix {
		a.mode = ModeCommand
		a.command = prefix
		a.updateHints()
		return
	}
	a.input += value
}

func (a *App) backspace() {
	if a.mode == ModeCommand {
		if len(a.command) > 0 {
			a.command = a.command[:len(a.command)-1]
			if len(a.command) == 0 {
				a.mode = ModeInsert
				a.hints = nil
				return
			}
			a.updateHints()
			return
		}
		a.mode = ModeInsert
		a.hints = nil
		return
	}
	if len(a.input) > 0 {
		a.input = a.input[:len(a.input)-1]
	}
}

func (a *App) handleEnter() (tea.Model, tea.Cmd) {
	if a.mode == ModeInsert {
		if trimmed := strings.TrimSpace(a.input); trimmed != "" {
			a.addMessage(trimmed)
			a.completed = append(a.completed, trimmed)
		}
		a.input = ""
		return a, nil
	}

	raw := strings.TrimSpace(a.command)
	a.command = ""
	if raw == "" {
		a.mode = ModeInsert
		a.hints = nil
		return a, nil
	}

	a.completed = append(a.completed, raw)
	cmd := a.executeCommand(raw)
	a.mode = ModeInsert
	a.hints = nil
	return a, cmd
}

func (a *App) executeCommand(raw string) tea.Cmd {
	a.log("command: %s", raw)

	prefix := string(a.cfg.CommandPrefix)
	if !strings.HasPrefix(raw, prefix) {
		a.log("commands must start with %s", prefix)
		return nil
	}

	content := strings.TrimSpace(raw[len(prefix):])
	if content == "" {
		a.log("missing command name")
		return nil
	}

	parts := strings.Fields(content)
	name := strings.ToLower(parts[0])
	args := parts[1:]

	switch name {
	case "connect":
		return a.commandConnect(args)
	case "register":
		return a.commandRegister(args)
	case "login":
		return a.commandLogin(args)
	case "quit", "exit":
		return a.commandQuit()
	default:
		a.log("unknown command: %s", name)
		return nil
	}
}

func (a *App) commandConnect(args []string) tea.Cmd {
	if a.session != nil {
		a.log("already connected")
		return nil
	}

	address := a.cfg.ServerAddr
	if len(args) > 0 {
		address = args[0]
	}
	if address == "" {
		a.log("no server address configured")
		return nil
	}

	a.log("connecting to %s ...", address)
	a.cfg.ServerAddr = address
	return connectCommand(a.cfg, address)
}

func (a *App) commandRegister(args []string) tea.Cmd {
	if !a.ensureConnected() {
		return nil
	}
	if len(args) < 2 {
		a.log("usage: /register <username> <password>")
		return nil
	}
	username := args[0]
	password := args[1]
	a.log("registering as %s...", username)
	a.pendingUser = username
	return tea.Batch(
		a.sendAuthRequest("register", username, password),
	)
}

func (a *App) commandLogin(args []string) tea.Cmd {
	if !a.ensureConnected() {
		return nil
	}
	if len(args) < 2 {
		a.log("usage: /login <username> <password>")
		return nil
	}
	username := args[0]
	password := args[1]
	a.log("logging in as %s...", username)
	a.pendingUser = username
	return tea.Batch(
		a.sendAuthRequest("login", username, password),
	)
}

func (a *App) updateHints() {
	if a.mode != ModeCommand {
		a.hints = nil
		return
	}
	prefix := string(a.cfg.CommandPrefix)
	if !strings.HasPrefix(a.command, prefix) {
		a.hints = nil
		return
	}
	typed := strings.TrimSpace(strings.TrimPrefix(a.command, prefix))
	var search string
	if typed != "" {
		parts := strings.Fields(typed)
		if len(parts) > 0 {
			search = strings.ToLower(parts[0])
		}
	}
	suggestions := make([]string, 0, maxCommandHints)
	for _, spec := range commandCatalog {
		if search == "" || strings.HasPrefix(spec.Name, search) {
			suggestions = append(suggestions, fmt.Sprintf("%s — %s", spec.Usage, spec.Description))
			if len(suggestions) >= maxCommandHints {
				break
			}
		}
	}
	a.hints = suggestions
}

func (a *App) ensureConnected() bool {
	if a.session == nil {
		a.log("not connected; use /connect first")
		return false
	}
	return true
}

func (a *App) sendAuthRequest(action, username, password string) tea.Cmd {
	session := a.session
	if session == nil {
		return nil
	}
	env := protocol.Envelope{
		Type: protocol.MessageTypeAuthRequest,
		Payload: protocol.AuthRequest{
			Action:   action,
			Username: username,
			Password: password,
		},
	}
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), authRequestTimeout)
		defer cancel()
		if err := session.Send(ctx, env); err != nil {
			return authSendResultMsg{Username: username, Err: err}
		}
		return authSendResultMsg{Username: username}
	}
}

func (a *App) commandQuit() tea.Cmd {
	a.log("closing client")
	if a.session != nil {
		_ = a.session.Close()
		a.session = nil
	}
	a.token = ""
	a.userID = ""
	a.pendingUser = ""
	a.username = ""
	a.mode = ModeInsert
	a.hints = nil
	return tea.Quit
}

func (a *App) handleConnectResult(msg connectResultMsg) (tea.Model, tea.Cmd) {
	if msg.Err != nil {
		a.log("connection failed: %v", msg.Err)
		return a, nil
	}

	if a.session != nil {
		_ = a.session.Close()
	}

	a.session = msg.Session
	a.log("connected to %s", msg.Address)
	a.token = ""
	a.userID = ""
	a.pendingUser = ""
	a.username = ""
	return a, listenForMessages(a.session)
}

func (a *App) handleEnvelope(msg envelopeMsg) (tea.Model, tea.Cmd) {
	if msg.Session != a.session || a.session == nil {
		return a, nil
	}
	if err := a.processEnvelope(msg.Envelope); err != nil {
		a.log("message error: %v", err)
	}
	return a, listenForMessages(a.session)
}

func (a *App) handleSessionClosed(msg sessionClosedMsg) (tea.Model, tea.Cmd) {
	if msg.Session != a.session || a.session == nil {
		return a, nil
	}
	a.session = nil
	a.token = ""
	a.userID = ""
	a.pendingUser = ""
	a.username = ""
	a.log("connection closed")
	return a, nil
}

func (a *App) handleAuthResult(msg authSendResultMsg) (tea.Model, tea.Cmd) {
	if msg.Err != nil {
		a.log("auth request failed: %v", msg.Err)
		if a.pendingUser == msg.Username {
			a.pendingUser = ""
		}
	}
	return a, nil
}

func (a *App) processEnvelope(env protocol.Envelope) error {
	switch env.Type {
	case protocol.MessageTypeAck:
		ack, err := decodeAckPayload(env.Payload)
		if err != nil {
			return err
		}
		status := strings.ToLower(ack.Status)
		if ack.Reason != "" {
			a.log("ack[%s]: %s", status, ack.Reason)
		} else {
			a.log("ack[%s]", status)
		}
		if status == ackStatusError {
			a.pendingUser = ""
		}
	case protocol.MessageTypeAuthResponse:
		resp, err := decodeAuthResponse(env.Payload)
		if err != nil {
			return err
		}
		a.token = resp.Token
		a.userID = resp.UserID
		username := a.pendingUser
		if username == "" {
			username = a.username
		}
		expires := time.Unix(resp.ExpiresAt, 0).Format(time.RFC3339)
		a.log("authenticated as %s (user id: %s, expires: %s)", username, resp.UserID, expires)
		a.pendingUser = ""
		if username != "" {
			a.username = username
		}
	default:
		a.log("received envelope type %s", env.Type)
	}
	return nil
}

func (a *App) log(format string, args ...interface{}) {
	a.logLine = fmt.Sprintf(format, args...)
}

func (a *App) addMessage(message string) {
	a.messages = append(a.messages, message)
	a.refreshViewport()
}

func (a *App) refreshViewport() {
	content := strings.Join(a.messages, "\n")
	atBottom := a.viewport.AtBottom()
	a.viewport.SetContent(content)
	if atBottom {
		a.viewport.GotoBottom()
	}
}

func (a *App) scrollMessages(lines int) {
	if lines > 0 {
		a.viewport.LineUp(lines)
	} else if lines < 0 {
		a.viewport.LineDown(-lines)
	}
}

func (a *App) resizeViewport(width, height int) {
	if width <= 0 || height <= 0 {
		return
	}
	const reservedLines = 7
	viewportHeight := height - reservedLines
	if viewportHeight < 3 {
		viewportHeight = 3
	}
	a.viewport.Width = width
	a.viewport.Height = viewportHeight
	a.refreshViewport()
}

// View renders the terminal UI.
func (a *App) View() string {
	var b strings.Builder
	b.WriteString(a.viewport.View())
	b.WriteString("\n")
	b.WriteString(separator())
	b.WriteString("\n")
	b.WriteString(a.renderInputLine())
	b.WriteString("\n")
	if hintLines := a.renderCommandHints(); len(hintLines) > 0 {
		for _, line := range hintLines {
			b.WriteString(line)
			b.WriteString("\n")
		}
	}
	if a.logLine != "" {
		b.WriteString(a.logLine)
		b.WriteString("\n")
	}
	b.WriteString(separator())
	b.WriteString("\n")
	b.WriteString(a.renderStatusBar())
	return b.String()
}

func separator() string {
	return strings.Repeat("-", 60)
}

func (a *App) renderStatusBar() string {
	mode := modeLabel(a.mode)
	status := "offline"
	server := "-"
	if a.session != nil {
		status = "connected"
		if addr := a.session.cfg.ServerAddr; addr != "" {
			server = addr
		}
	} else if a.cfg.ServerAddr != "" {
		server = a.cfg.ServerAddr
	}
	user := "-"
	switch {
	case a.pendingUser != "":
		user = a.pendingUser + "*"
	case a.username != "":
		user = a.username
	case a.token != "":
		user = "authenticated"
	}
	room := "-"
	return fmt.Sprintf("GoSlash | Mode:%s | Status:%s | Server:%s | User:%s | Room:%s", mode, status, server, user, room)
}

func (a *App) renderCommandHints() []string {
	if a.mode != ModeCommand || len(a.hints) == 0 {
		return nil
	}
	lines := make([]string, 0, len(a.hints)+1)
	lines = append(lines, "Hints:")
	for _, hint := range a.hints {
		lines = append(lines, "  "+hint)
	}
	return lines
}

func (a *App) renderInputLine() string {
	if a.mode == ModeCommand {
		prefix := string(a.cfg.CommandPrefix)
		typed := strings.TrimPrefix(a.command, prefix)
		return fmt.Sprintf("%c%s%s", a.cfg.CommandPrefix, typed, cursorIndicator)
	}
	return fmt.Sprintf("%s%s", a.input, cursorIndicator)
}

func modeLabel(mode Mode) string {
	switch mode {
	case ModeCommand:
		return "COMMAND"
	case ModeInsert:
		return "INSERT"
	default:
		return "UNKNOWN"
	}
}

type connectResultMsg struct {
	Address string
	Session *Session
	Err     error
}

type envelopeMsg struct {
	Session  *Session
	Envelope protocol.Envelope
}

type sessionClosedMsg struct {
	Session *Session
}

type authSendResultMsg struct {
	Username string
	Err      error
}

const (
	connectTimeout     = 5 * time.Second
	authRequestTimeout = 5 * time.Second
	maxCommandHints    = 5
	cursorIndicator    = "|"
)

const ackStatusError = "error"

type commandSpec struct {
	Name        string
	Usage       string
	Description string
}

var commandCatalog = []commandSpec{
	{
		Name:        "connect",
		Usage:       "/connect [address]",
		Description: "Connect to a GoSlash server",
	},
	{
		Name:        "register",
		Usage:       "/register <username> <password>",
		Description: "Create a new account on the server",
	},
	{
		Name:        "login",
		Usage:       "/login <username> <password>",
		Description: "Authenticate with an existing account",
	},
	{
		Name:        "quit",
		Usage:       "/quit",
		Description: "Exit the GoSlash client (alias: /exit)",
	},
}

func connectCommand(cfg config.ClientConfig, address string) tea.Cmd {
	return func() tea.Msg {
		sessionCfg := cfg
		sessionCfg.ServerAddr = address
		session := NewSession(sessionCfg)

		ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
		defer cancel()

		if err := session.Connect(ctx); err != nil {
			_ = session.Close()
			return connectResultMsg{Address: address, Err: err}
		}

		return connectResultMsg{Address: address, Session: session}
	}
}

func listenForMessages(session *Session) tea.Cmd {
	if session == nil {
		return nil
	}
	ch := session.Messages()
	return func() tea.Msg {
		env, ok := <-ch
		if !ok {
			return sessionClosedMsg{Session: session}
		}
		return envelopeMsg{Session: session, Envelope: env}
	}
}

func decodeAckPayload(payload interface{}) (protocol.AckPayload, error) {
	var ack protocol.AckPayload
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
	data, err := json.Marshal(payload)
	if err != nil {
		return resp, err
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return resp, err
	}
	return resp, nil
}
