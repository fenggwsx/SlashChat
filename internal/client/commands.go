package client

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/uuid"

	"github.com/fenggwsx/SlashChat/internal/protocol"
)

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
	case "/pipe":
		if len(fields) > 1 && strings.EqualFold(fields[1], "clear") {
			a.pipeHistory = make([]pipeEntry, 0, pipeHistoryLimit)
			a.logf("Cleared pipe history")
			if a.view == viewPipe {
				a.updateViewportContent()
			}
			break
		}
		a.view = viewPipe
		a.logf("Switched to PIPE view")
		a.updateViewportContent()
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
	if a.view != viewChat && a.view != viewPipe && a.hasActiveRoom() {
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
	if envCopy.Timestamp.IsZero() {
		envCopy.Timestamp = time.Now().UTC()
	}
	if attachToken && envCopy.Token == "" && strings.TrimSpace(a.authToken) != "" {
		envCopy.Token = a.authToken
	}
	a.appendPipeEntry(pipeDirectionOut, envCopy)
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := session.Send(ctx, envCopy)
		return sendResultMsg{
			session:     session,
			id:          envCopy.ID,
			description: description,
			err:         err,
		}
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
		{trigger: "/pipe", usage: "/pipe [clear]", description: "Inspect transport JSON frames"},
		{trigger: "/quit", usage: "/quit", description: "Exit the client"},
	}
}
