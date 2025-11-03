package client

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	figure "github.com/common-nighthawk/go-figure"
	"github.com/google/uuid"
	"github.com/mattn/go-runewidth"

	"github.com/fenggwsx/SlashChat/internal/config"
	"github.com/fenggwsx/SlashChat/internal/protocol"
)

type activeView int

const (
	viewChat activeView = iota
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

type logLevel int

const (
	logLevelInfo logLevel = iota
	logLevelError
)

type logMessage struct {
	label string
	body  string
	level logLevel
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
			if _, ok := a.pendingRequests[m.id]; ok {
				delete(a.pendingRequests, m.id)
			}
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

	return a.sendChatMessage(value)
}

func (a *App) executeCommand(raw string) tea.Cmd {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return nil
	}

	cmd := fields[0]
	var cmds []tea.Cmd

	switch cmd {
	case "/chat":
		a.view = viewChat
		a.logf("Switched to CHAT view")
	case "/help":
		a.view = viewHelp
		a.logf("Switched to HELP view")
	case "/join":
		if len(fields) < 2 {
			a.logErrorf("Usage: /join <room>")
			break
		}
		if !a.isConnected() {
			a.logErrorf("Not connected. Use /connect first.")
			break
		}
		room := fields[1]
		if strings.EqualFold(strings.TrimSpace(room), strings.TrimSpace(a.room)) {
			a.logf("Already in room %s", room)
			break
		}
		a.logf("Joining room %s ...", room)
		if joinCmd := a.sendJoinCommand(room); joinCmd != nil {
			cmds = append(cmds, joinCmd)
		}
	case "/leave":
		if !a.isConnected() {
			a.logErrorf("Not connected. Use /connect first.")
			break
		}
		targetRoom := strings.TrimSpace(a.room)
		if len(fields) > 1 {
			targetRoom = fields[1]
		}
		if targetRoom == "" || targetRoom == "-" {
			a.logErrorf("No active room to leave")
			break
		}
		a.logf("Leaving room %s ...", targetRoom)
		if leaveCmd := a.sendLeaveCommand(targetRoom); leaveCmd != nil {
			cmds = append(cmds, leaveCmd)
		}
	case "/connect":
		target := a.serverAddr
		if len(fields) > 1 {
			target = fields[1]
		}
		if target == "" {
			a.logErrorf("Provide a server address to connect")
			break
		}
		if connectCmd := a.connectToServer(target); connectCmd != nil {
			cmds = append(cmds, connectCmd)
		}
	case "/register":
		if len(fields) < 3 {
			a.logErrorf("Usage: /register <username> <password>")
			break
		}
		if !a.isConnected() {
			a.logErrorf("Not connected. Use /connect first.")
			break
		}
		username := fields[1]
		password := strings.Join(fields[2:], " ")
		if strings.TrimSpace(password) == "" {
			a.logErrorf("Password cannot be empty")
			break
		}
		a.logf("Registering %s ...", username)
		if authCmd := a.sendAuthCommand("register", username, password); authCmd != nil {
			cmds = append(cmds, authCmd)
		}
	case "/upload":
		if len(fields) < 2 {
			a.logErrorf("Usage: /upload <path>")
			break
		}
		if !a.isConnected() {
			a.logErrorf("Not connected. Use /connect first.")
			break
		}
		activeRoom := strings.TrimSpace(a.room)
		if activeRoom == "" || activeRoom == "-" {
			a.logErrorf("Join a room before uploading")
			break
		}
		path := strings.Join(fields[1:], " ")
		if uploadCmd := a.startFileUpload(path); uploadCmd != nil {
			cmds = append(cmds, uploadCmd)
		}
	case "/download":
		if len(fields) < 2 {
			a.logErrorf("Usage: /download <message_id>")
			break
		}
		if !a.isConnected() {
			a.logErrorf("Not connected. Use /connect first.")
			break
		}
		if !a.hasActiveRoom() {
			a.logErrorf("Join a room before downloading")
			break
		}
		messageID := strings.TrimSpace(fields[1])
		if downloadCmd := a.startFileDownload(messageID); downloadCmd != nil {
			cmds = append(cmds, downloadCmd)
		}
	case "/login":
		if len(fields) < 3 {
			a.logErrorf("Usage: /login <username> <password>")
			break
		}
		if !a.isConnected() {
			a.logErrorf("Not connected. Use /connect first.")
			break
		}
		username := fields[1]
		password := strings.Join(fields[2:], " ")
		if strings.TrimSpace(password) == "" {
			a.logErrorf("Password cannot be empty")
			break
		}
		a.logf("Logging in as %s ...", username)
		if authCmd := a.sendAuthCommand("login", username, password); authCmd != nil {
			cmds = append(cmds, authCmd)
		}
	case "/quit":
		a.logf("Exiting client")
		if a.session != nil {
			_ = a.session.Close()
			a.session = nil
		}
		a.statusOnline = false
		a.authToken = ""
		cmds = append(cmds, tea.Quit)
	default:
		a.logErrorf("Command %s not implemented", cmd)
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

func (a *App) sendJoinCommand(room string) tea.Cmd {
	session := a.session
	if session == nil {
		return nil
	}
	room = strings.TrimSpace(room)
	if room == "" {
		return nil
	}
	if a.pendingRequests == nil {
		a.pendingRequests = make(map[string]pendingRequest)
	}
	requestID := uuid.NewString()
	a.pendingRequests[requestID] = pendingRequest{action: "join", room: room}

	env := protocol.Envelope{
		ID:   requestID,
		Type: protocol.MessageTypeCommand,
		Metadata: map[string]interface{}{
			"action": "join",
			"room":   room,
		},
		Payload: protocol.JoinRequest{Room: room},
	}

	return a.sendEnvelope(session, env, fmt.Sprintf("join %s", room), true)
}

func (a *App) sendLeaveCommand(room string) tea.Cmd {
	session := a.session
	if session == nil {
		return nil
	}
	room = strings.TrimSpace(room)
	if room == "" {
		return nil
	}
	if a.pendingRequests == nil {
		a.pendingRequests = make(map[string]pendingRequest)
	}
	requestID := uuid.NewString()
	a.pendingRequests[requestID] = pendingRequest{action: "leave", room: room}

	env := protocol.Envelope{
		ID:   requestID,
		Type: protocol.MessageTypeCommand,
		Metadata: map[string]interface{}{
			"action": "leave",
			"room":   room,
		},
		Payload: protocol.LeaveRequest{Room: room},
	}

	return a.sendEnvelope(session, env, fmt.Sprintf("leave %s", room), true)
}

func (a *App) startFileUpload(path string) tea.Cmd {
	session := a.session
	if session == nil {
		return nil
	}
	room := strings.TrimSpace(a.room)
	if room == "" || room == "-" {
		a.logErrorf("Join a room before uploading")
		return nil
	}
	path = strings.TrimSpace(path)
	if path == "" {
		a.logErrorf("Usage: /upload <path>")
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		a.logErrorf("Cannot access %s: %v", path, err)
		return nil
	}
	if info.IsDir() {
		a.logErrorf("Cannot upload a directory")
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		a.logErrorf("Cannot read %s: %v", path, err)
		return nil
	}
	sum := sha256.Sum256(data)
	sha := fmt.Sprintf("%x", sum[:])
	encoded := base64.StdEncoding.EncodeToString(data)
	filename := filepath.Base(path)
	size := info.Size()

	if a.pendingRequests == nil {
		a.pendingRequests = make(map[string]pendingRequest)
	}
	requestID := uuid.NewString()
	a.pendingRequests[requestID] = pendingRequest{
		action:   "file_upload_prepare",
		room:     room,
		filePath: path,
		fileName: filename,
		sha:      sha,
		data:     encoded,
		size:     size,
	}

	a.logf("Preparing to upload %s (%d bytes) to %s ...", filename, size, room)

	env := protocol.Envelope{
		ID:   requestID,
		Type: protocol.MessageTypeCommand,
		Metadata: map[string]interface{}{
			"action": "file_upload_prepare",
			"room":   room,
		},
		Payload: protocol.FileUploadRequest{
			Room:     room,
			Filename: filename,
			SHA256:   sha,
			Size:     size,
		},
	}

	return a.sendEnvelope(session, env, "file upload prepare", true)
}

func (a *App) sendFileUpload(p pendingRequest) tea.Cmd {
	session := a.session
	if session == nil {
		return nil
	}
	room := strings.TrimSpace(p.room)
	if room == "" || room == "-" {
		a.logErrorf("No active room to receive upload")
		return nil
	}
	if strings.TrimSpace(p.data) == "" {
		a.logErrorf("No file data available for upload")
		return nil
	}
	if a.pendingRequests == nil {
		a.pendingRequests = make(map[string]pendingRequest)
	}
	requestID := uuid.NewString()
	a.pendingRequests[requestID] = pendingRequest{
		action:   "file_upload",
		room:     room,
		fileName: p.fileName,
		sha:      p.sha,
		size:     p.size,
	}

	a.logf("Uploading %s to %s ...", p.fileName, room)

	env := protocol.Envelope{
		ID:   requestID,
		Type: protocol.MessageTypeFileUpload,
		Metadata: map[string]interface{}{
			"room":   room,
			"action": "file_upload",
		},
		Payload: protocol.FileUploadPayload{
			Room:       room,
			Filename:   p.fileName,
			SHA256:     p.sha,
			DataBase64: p.data,
		},
	}

	return a.sendEnvelope(session, env, "file upload", true)
}

func (a *App) startFileDownload(messageID string) tea.Cmd {
	session := a.session
	if session == nil {
		return nil
	}

	if a.pendingRequests == nil {
		a.pendingRequests = make(map[string]pendingRequest)
	}

	value := strings.TrimSpace(messageID)
	if value == "" {
		a.logErrorf("Usage: /download <message_id>")
		return nil
	}

	idValue, err := strconv.ParseUint(value, 10, 64)
	if err != nil || idValue == 0 {
		a.logErrorf("Invalid message id: %s", value)
		return nil
	}

	id := uint(idValue)
	requestID := uuid.NewString()
	a.pendingRequests[requestID] = pendingRequest{action: "file_download", messageID: id}
	a.logf("Requesting download for message #%d ...", id)

	env := protocol.Envelope{
		ID:   requestID,
		Type: protocol.MessageTypeCommand,
		Metadata: map[string]interface{}{
			"action":     "file_download",
			"message_id": fmt.Sprintf("%d", id),
		},
		Payload: protocol.FileDownloadRequest{MessageID: id},
	}

	return a.sendEnvelope(session, env, "file download", true)
}

func (a *App) sendChatMessage(content string) tea.Cmd {
	content = strings.TrimSpace(content)
	if content == "" {
		return nil
	}
	if !a.isConnected() {
		a.logErrorf("Not connected. Use /connect first.")
		return nil
	}
	if strings.TrimSpace(a.authToken) == "" {
		a.logErrorf("Authenticate before chatting (use /login or /register)")
		return nil
	}
	room := strings.TrimSpace(a.room)
	if room == "" || room == "-" {
		a.logErrorf("Join a room before chatting (use /join <room>)")
		return nil
	}
	session := a.session
	if session == nil {
		return nil
	}
	if a.pendingRequests == nil {
		a.pendingRequests = make(map[string]pendingRequest)
	}
	if a.view != viewChat && a.hasActiveRoom() {
		a.view = viewChat
		a.updateViewportContent()
	}
	requestID := uuid.NewString()
	a.pendingRequests[requestID] = pendingRequest{action: "chat_send", room: room}
	a.logf("Sending message to %s ...", room)

	env := protocol.Envelope{
		ID:   requestID,
		Type: protocol.MessageTypeEvent,
		Metadata: map[string]interface{}{
			"action": "chat_send",
			"room":   room,
		},
		Payload: protocol.ChatSendRequest{Room: room, Content: content},
	}

	return a.sendEnvelope(session, env, "chat message", true)
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

func (a *App) handleSessionEnvelope(env protocol.Envelope) tea.Cmd {
	switch env.Type {
	case protocol.MessageTypeAck:
		return a.handleAckEnvelope(env)
	case protocol.MessageTypeAuthResponse:
		a.handleAuthResponse(env)
	case protocol.MessageTypeEvent:
		a.handleEventEnvelope(env)
	case protocol.MessageTypeFileDownload:
		a.handleFileDownload(env)
	default:
		a.logErrorf("Received %s message", string(env.Type))
	}
	return nil
}

func (a *App) handleAckEnvelope(env protocol.Envelope) tea.Cmd {
	ack, err := decodeAckPayload(env.Payload)
	if err != nil {
		a.logErrorf("Failed to decode ack: %v", err)
		return nil
	}

	pending, ok := a.pendingRequests[ack.ReferenceID]
	if !ok {
		if ack.Reason != "" {
			a.logf("Server response: %s", ack.Reason)
		}
		return nil
	}
	delete(a.pendingRequests, ack.ReferenceID)

	status := strings.ToLower(strings.TrimSpace(ack.Status))
	action := strings.ToLower(pending.action)

	switch status {
	case "ok":
		switch action {
		case "register":
			a.logf("Registration accepted for %s", pending.username)
		case "login":
			a.logf("Login accepted for %s", pending.username)
		case "join":
			a.logf("Joined room %s", pending.room)
		case "leave":
			a.logf("Left room %s", pending.room)
			if strings.EqualFold(strings.TrimSpace(a.room), strings.TrimSpace(pending.room)) {
				a.room = "-"
				a.chatHistory = nil
				a.updateViewportContent()
			}
		case "file_upload_prepare":
			a.logf("Upload skipped; server already has %s", pending.fileName)
		case "file_upload":
			a.logf("Uploaded %s to %s", pending.fileName, pending.room)
		case "chat_send":
			a.logf("Message delivered to %s", pending.room)
		case "file_download":
			a.logf("Download accepted for message #%d", pending.messageID)
		default:
			a.logf("Command %s acknowledged", pending.action)
		}
		if action == "register" || action == "login" {
			a.lastAuthAction = pending.action
			a.lastAuthUser = pending.username
		}
		return nil
	case "upload_required":
		if action == "file_upload_prepare" {
			a.logf("Server requested upload for %s", pending.fileName)
			return a.sendFileUpload(pending)
		}
		a.logf("Server requested upload retry")
		return nil
	default:
		reason := strings.TrimSpace(ack.Reason)
		if reason == "" {
			reason = "unknown error"
		}
		switch action {
		case "register":
			a.logErrorf("Registration failed: %s", reason)
		case "login":
			a.logErrorf("Login failed: %s", reason)
		case "join":
			a.logErrorf("Join failed: %s", reason)
		case "leave":
			a.logErrorf("Leave failed: %s", reason)
		case "chat_send":
			a.logErrorf("Message failed: %s", reason)
		case "file_upload_prepare":
			a.logErrorf("Upload prepare failed: %s", reason)
		case "file_upload":
			a.logErrorf("Upload failed: %s", reason)
		case "file_download":
			a.logErrorf("Download failed: %s", reason)
		default:
			a.logErrorf("Command %s failed: %s", pending.action, reason)
		}
		if action == "register" || action == "login" {
			a.lastAuthAction = ""
			a.lastAuthUser = ""
		}
		return nil
	}
}

func (a *App) handleAuthResponse(env protocol.Envelope) {
	resp, err := decodeAuthResponse(env.Payload)
	if err != nil {
		a.logErrorf("Failed to decode auth response: %v", err)
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

	a.logf("%s", message)
	a.lastAuthAction = ""
	a.lastAuthUser = ""
}

func (a *App) handleEventEnvelope(env protocol.Envelope) {
	action := strings.ToLower(metadataString(env.Metadata, "action"))
	switch action {
	case "chat_history":
		a.handleChatHistory(env)
	case "chat_message":
		a.handleChatMessage(env)
	default:
		a.logErrorf("Unhandled event action: %s", action)
	}
}

func (a *App) handleFileDownload(env protocol.Envelope) {
	payload, err := decodeFileDownloadPayload(env.Payload)
	if err != nil {
		a.logErrorf("Failed to decode download payload: %v", err)
		return
	}

	if payload.MessageID == 0 {
		a.logErrorf("Download payload missing message id")
		return
	}

	data, err := base64.StdEncoding.DecodeString(payload.DataBase64)
	if err != nil {
		a.logErrorf("Failed to decode download data: %v", err)
		return
	}

	path, err := a.writeDownloadedFile(payload.Filename, payload.SHA256, data)
	if err != nil {
		a.logErrorf("Failed to save download: %v", err)
		return
	}

	name := strings.TrimSpace(payload.Filename)
	if name == "" {
		name = filepath.Base(path)
	}
	a.logf("Downloaded %s from message #%d to %s", name, payload.MessageID, path)
}

func (a *App) isConnected() bool {
	return a.session != nil && a.statusOnline
}

func (a *App) handleChatHistory(env protocol.Envelope) {
	history, err := decodeChatHistory(env.Payload)
	if err != nil {
		a.logErrorf("Failed to decode chat history: %v", err)
		return
	}
	r := strings.TrimSpace(history.Room)
	if r == "" {
		a.logErrorf("Received chat history without room")
		return
	}
	a.room = r
	a.chatHistory = make([]string, 0, len(history.Messages))
	for _, msg := range history.Messages {
		a.chatHistory = append(a.chatHistory, a.formatChatMessage(msg))
	}
	a.updateViewportContent()
	if a.view == viewChat {
		a.viewport.GotoBottom()
	}
	a.logf("Loaded %d messages for %s", len(history.Messages), r)
}

func (a *App) handleChatMessage(env protocol.Envelope) {
	msg, err := decodeChatMessage(env.Payload)
	if err != nil {
		a.logErrorf("Failed to decode chat message: %v", err)
		return
	}
	room := strings.TrimSpace(msg.Room)
	if room == "" {
		return
	}
	if !strings.EqualFold(strings.TrimSpace(a.room), room) {
		// Message for another room; future enhancement could queue it.
		return
	}
	a.appendChatLine(a.formatChatMessage(msg))
}

func (a *App) appendChatLine(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	a.chatHistory = append(a.chatHistory, line)
	if a.view == viewChat {
		a.updateViewportContent()
		a.viewport.GotoBottom()
	}
}

func (a *App) formatChatMessage(msg protocol.ChatMessage) string {
	username := strings.TrimSpace(msg.Username)
	if username == "" {
		username = "unknown"
	}
	timestamp := ""
	if msg.CreatedAt > 0 {
		timestamp = time.Unix(msg.CreatedAt, 0).Local().Format("15:04:05")
	}
	idPrefix := fmt.Sprintf("[#%d]", msg.ID)
	body := a.renderMessageBody(msg)
	if timestamp != "" {
		return fmt.Sprintf("%s [%s] %s: %s", idPrefix, timestamp, username, body)
	}
	return fmt.Sprintf("%s %s: %s", idPrefix, username, body)
}

func (a *App) renderMessageBody(msg protocol.ChatMessage) string {
	switch msg.Kind {
	case protocol.MessageKindFile:
		name := strings.TrimSpace(msg.Filename)
		if name == "" {
			name = strings.TrimSpace(msg.Content)
		}
		if name == "" {
			name = "file"
		}
		if msg.SHA256 != "" {
			return fmt.Sprintf("uploaded file %s (sha256: %s)", name, msg.SHA256)
		}
		return fmt.Sprintf("uploaded file %s", name)
	default:
		content := strings.TrimSpace(msg.Content)
		if content == "" {
			content = "(empty)"
		}
		return content
	}
}

func (a *App) writeDownloadedFile(name, sha string, data []byte) (string, error) {
	base := strings.TrimSpace(name)
	if base == "" {
		base = strings.TrimSpace(sha)
	}
	if base == "" {
		base = fmt.Sprintf("download_%d", time.Now().Unix())
	}
	base = filepath.Base(base)
	if base == "" || base == "." || base == string(filepath.Separator) {
		base = fmt.Sprintf("download_%d", time.Now().Unix())
	}

	candidate := base
	for i := 0; i < 100; i++ {
		path := filepath.Join(".", candidate)
		_, err := os.Stat(path)
		if err == nil {
			ext := filepath.Ext(base)
			stem := strings.TrimSuffix(base, ext)
			candidate = fmt.Sprintf("%s(%d)%s", stem, i+1, ext)
			continue
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return "", err
		}
		return path, nil
	}

	return "", fmt.Errorf("unable to create file for %s", base)
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
		a.styles.title.Render("SlashChat"),
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

func defaultCommands() []commandSpec {
	return []commandSpec{
		{trigger: "/connect", usage: "/connect [addr]", description: "Connect to the server"},
		{trigger: "/register", usage: "/register <username> <password>", description: "Register a new account"},
		{trigger: "/login", usage: "/login <username> <password>", description: "Authenticate with existing credentials"},
		{trigger: "/chat", usage: "/chat", description: "Switch to chat view"},
		{trigger: "/help", usage: "/help", description: "Show command help"},
		{trigger: "/join", usage: "/join <room>", description: "Join a room"},
		{trigger: "/leave", usage: "/leave", description: "Leave current room"},
		{trigger: "/upload", usage: "/upload <path>", description: "Upload a file"},
		{trigger: "/download", usage: "/download <message_id>", description: "Download a file shared in chat"},
		{trigger: "/quit", usage: "/quit", description: "Exit the client"},
	}
}

func (v activeView) String() string {
	switch v {
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

var homeContent = buildHomeContent()

func buildHomeContent() string {
	fig := figure.NewColorFigure("SLASH CHAT", "3-d", "green", true)
	art := strings.TrimRight(fig.String(), "\n")
	info := []string{
		"Use /connect to reach the server.",
		"Use /register or /login after connecting.",
		"Use /join <room> to load chat history.",
		"Use /download <message_id> to retrieve shared files.",
		"Use /help to browse all commands.",
	}

	var b strings.Builder
	b.WriteString(art)
	b.WriteString("\n\n")
	b.WriteString(strings.Join(info, "\n"))
	return b.String()
}

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
		title:         base.Foreground(lipgloss.Color("13")).Bold(true), // bright magenta
		view:          base.Foreground(lipgloss.Color("14")).Bold(true), // bright cyan
		statusOnline:  base.Foreground(lipgloss.Color("10")).Bold(true), // bright green
		statusOffline: base.Foreground(lipgloss.Color("9")).Bold(true),  // bright red
		label:         base.Foreground(lipgloss.Color("8")),             // bright black / gray
		value:         base.Foreground(lipgloss.Color("15")),            // bright white
		logLabel:      base.Foreground(lipgloss.Color("11")).Bold(true), // bright yellow
		logBody:       base.Foreground(lipgloss.Color("7")),             // white
		logLabelError: base.Foreground(lipgloss.Color("9")).Bold(true),  // bright red
		logBodyError:  base.Foreground(lipgloss.Color("9")),             // bright red
		help:          base.Foreground(lipgloss.Color("12")),            // bright blue
	}
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

func decodeChatHistory(payload interface{}) (protocol.ChatHistory, error) {
	var history protocol.ChatHistory
	if payload == nil {
		return history, fmt.Errorf("chat history payload empty")
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return history, err
	}
	if err := json.Unmarshal(data, &history); err != nil {
		return history, err
	}
	return history, nil
}

func decodeChatMessage(payload interface{}) (protocol.ChatMessage, error) {
	var msg protocol.ChatMessage
	if payload == nil {
		return msg, fmt.Errorf("chat message payload empty")
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return msg, err
	}
	if err := json.Unmarshal(data, &msg); err != nil {
		return msg, err
	}
	return msg, nil
}

func decodeFileDownloadPayload(payload interface{}) (protocol.FileDownloadPayload, error) {
	var dl protocol.FileDownloadPayload
	if payload == nil {
		return dl, fmt.Errorf("download payload empty")
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return dl, err
	}
	if err := json.Unmarshal(data, &dl); err != nil {
		return dl, err
	}
	return dl, nil
}

func metadataString(metadata map[string]interface{}, key string) string {
	if metadata == nil {
		return ""
	}
	if value, ok := metadata[key]; ok {
		if s, ok := value.(string); ok {
			return s
		}
	}
	return ""
}
