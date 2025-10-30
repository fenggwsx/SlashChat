package client

import (
	"fmt"
	"strings"

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

	cmd := strings.TrimSpace(a.command)
	if cmd == "" {
		return a, nil
	}

	a.messages = append(a.messages, fmt.Sprintf("executing %s", cmd))
	a.completed = append(a.completed, cmd)
	a.command = ""
	return a, nil
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
