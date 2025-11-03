package client

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/fenggwsx/SlashChat/internal/config"
	"github.com/fenggwsx/SlashChat/internal/protocol"
)

type activeView int

const (
	viewChat activeView = iota
	viewHelp
	viewPipe
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

	pipeHistory []pipeEntry

	styles styleSet
}

type commandSpec struct {
	trigger     string
	usage       string
	description string
}

type logLevel int

const (
	logLevelInfo logLevel = iota
	logLevelError
)

type pipeDirection string

const (
	pipeDirectionOut pipeDirection = "->"
	pipeDirectionIn  pipeDirection = "<-"
)

const pipeHistoryLimit = 200

type logMessage struct {
	label string
	body  string
	level logLevel
}

type pipeEntry struct {
	direction   pipeDirection
	messageType string
	timestamp   time.Time
	body        string
}

type pendingRequest struct {
	action    string
	username  string
	room      string
	filePath  string
	fileName  string
	sha       string
	data      string
	size      int64
	messageID uint
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
	logLabelError lipgloss.Style
	logBodyError  lipgloss.Style
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
		view:       viewChat,
		serverAddr: cfg.ServerAddr,

		viewport: vp,
		input:    input,
		helper:   helper,

		logLine: logMessage{label: "[msg]", body: "GoSlash client ready", level: logLevelInfo},

		statusOnline: false,
		username:     "guest",
		room:         "-",

		chatHistory:     []string{},
		commands:        defaultCommands(),
		pendingRequests: make(map[string]pendingRequest),
		pipeHistory:     make([]pipeEntry, 0, pipeHistoryLimit),

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

		if m.Type == tea.KeyTab {
			if a.handleTabCompletion() {
				a.updateHelp()
				a.updateViewportContent()
				return a, nil
			}
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
			a.logErrorf("Failed to connect to %s: %v", m.address, m.err)
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
		cmd := a.handleSessionEnvelope(m.envelope)
		if cmd != nil {
			return a, tea.Batch(cmd, a.listenForSession())
		}
		return a, a.listenForSession()

	case sessionClosedMsg:
		if m.session != a.session {
			return a, nil
		}
		a.statusOnline = false
		a.authToken = ""
		a.logf("Disconnected from %s", a.serverAddr)
		a.session = nil
		return a, nil

	case sendResultMsg:
		if m.session != a.session {
			return a, nil
		}
		if m.err != nil {
			delete(a.pendingRequests, m.id)
			a.logErrorf("%s failed: %v", m.description, m.err)
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
func (a *App) logf(format string, args ...any) {
	a.logLine = logMessage{
		label: "[msg]",
		body:  fmt.Sprintf(format, args...),
		level: logLevelInfo,
	}
}

func (a *App) logErrorf(format string, args ...any) {
	a.logLine = logMessage{
		label: "[err]",
		body:  fmt.Sprintf(format, args...),
		level: logLevelError,
	}
}

func (v activeView) String() string {
	switch v {
	case viewChat:
		return "chat"
	case viewHelp:
		return "help"
	case viewPipe:
		return "pipe"
	default:
		return "unknown"
	}
}
