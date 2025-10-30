package client

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/fenggwsx/SlashChat/internal/config"
)

// App implements the bubbletea tea.Model interface for the terminal client.
type App struct {
	cfg       config.ClientConfig
	mode      Mode
	command   string
	input     string
	messages  []string
	completed []string
	session   *Session
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
	return &App{
		cfg:      cfg,
		mode:     ModeCommand,
		messages: make([]string, 0, 128),
	}
}

// Init is part of the tea.Model interface.
func (a *App) Init() tea.Cmd {
	return nil
}

// Update handles user input and internal events.
func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m := msg.(type) {
	case tea.KeyMsg:
		return a.handleKey(m)
	case connectResultMsg:
		return a.handleConnectResult(m)
	}
	return a, nil
}

func (a *App) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEsc:
		a.mode = ModeCommand
		a.command = ""
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
		if len(a.command) == 0 && value == string(a.cfg.CommandPrefix) {
			a.command = value
			return
		}
		a.command += value
		return
	}
	a.input += value
}

func (a *App) backspace() {
	if a.mode == ModeCommand {
		if len(a.command) > 0 {
			a.command = a.command[:len(a.command)-1]
		}
		return
	}
	if len(a.input) > 0 {
		a.input = a.input[:len(a.input)-1]
	}
}

func (a *App) handleEnter() (tea.Model, tea.Cmd) {
	if a.mode == ModeInsert {
		if trimmed := strings.TrimSpace(a.input); trimmed != "" {
			a.messages = append(a.messages, trimmed)
			a.completed = append(a.completed, trimmed)
		}
		a.input = ""
		return a, nil
	}

	raw := strings.TrimSpace(a.command)
	a.command = ""
	if raw == "" {
		return a, nil
	}

	a.completed = append(a.completed, raw)
	return a, a.executeCommand(raw)
}

func (a *App) executeCommand(raw string) tea.Cmd {
	a.pushMessage("> %s", raw)

	prefix := string(a.cfg.CommandPrefix)
	if !strings.HasPrefix(raw, prefix) {
		a.pushMessage("commands must start with %s", prefix)
		return nil
	}

	content := strings.TrimSpace(raw[len(prefix):])
	if content == "" {
		a.pushMessage("missing command name")
		return nil
	}

	parts := strings.Fields(content)
	name := strings.ToLower(parts[0])
	args := parts[1:]

	switch name {
	case "connect":
		return a.commandConnect(args)
	case "quit", "exit":
		return a.commandQuit()
	default:
		a.pushMessage("unknown command: %s", name)
		return nil
	}
}

func (a *App) commandConnect(args []string) tea.Cmd {
	if a.session != nil {
		a.pushMessage("already connected")
		return nil
	}

	address := a.cfg.ServerAddr
	if len(args) > 0 {
		address = args[0]
	}
	if address == "" {
		a.pushMessage("no server address configured")
		return nil
	}

	a.pushMessage("connecting to %s ...", address)
	a.cfg.ServerAddr = address
	return connectCommand(a.cfg, address)
}

func (a *App) commandQuit() tea.Cmd {
	a.pushMessage("closing client")
	if a.session != nil {
		_ = a.session.Close()
		a.session = nil
	}
	return tea.Quit
}

func (a *App) handleConnectResult(msg connectResultMsg) (tea.Model, tea.Cmd) {
	if msg.Err != nil {
		a.pushMessage("connection failed: %v", msg.Err)
		return a, nil
	}

	if a.session != nil {
		_ = a.session.Close()
	}

	a.session = msg.Session
	a.pushMessage("connected to %s", msg.Address)
	return a, nil
}

func (a *App) pushMessage(format string, args ...interface{}) {
	a.messages = append(a.messages, fmt.Sprintf(format, args...))
}

// View renders the terminal UI.
func (a *App) View() string {
	var b strings.Builder
	b.WriteString(titleBar(a.mode))
	b.WriteString("\n")
	for _, msg := range a.messages {
		b.WriteString(msg)
		b.WriteString("\n")
	}
	b.WriteString(separator())
	b.WriteString("\n")
	if a.mode == ModeCommand {
		b.WriteString(fmt.Sprintf("[%c] %s", a.cfg.CommandPrefix, a.command))
	} else {
		b.WriteString(a.input)
	}
	return b.String()
}

func titleBar(mode Mode) string {
	var label string
	switch mode {
	case ModeCommand:
		label = "COMMAND"
	case ModeInsert:
		label = "INSERT"
	default:
		label = "UNKNOWN"
	}
	return fmt.Sprintf("GoSlash :: %s mode", label)
}

func separator() string {
	return strings.Repeat("-", 40)
}

type connectResultMsg struct {
	Address string
	Session *Session
	Err     error
}

const connectTimeout = 5 * time.Second

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
