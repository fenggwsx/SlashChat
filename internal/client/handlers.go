package client

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/fenggwsx/SlashChat/internal/protocol"
)

func (a *App) handleSessionEnvelope(env protocol.Envelope) tea.Cmd {
	a.appendPipeEntry(pipeDirectionIn, env)
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

func (a *App) appendPipeEntry(direction pipeDirection, env protocol.Envelope) {
	if a.pipeHistory == nil {
		a.pipeHistory = make([]pipeEntry, 0, pipeHistoryLimit)
	}
	bodyBytes, err := json.MarshalIndent(env, "", "  ")
	entry := pipeEntry{
		direction:   direction,
		messageType: string(env.Type),
		timestamp:   time.Now(),
		body:        string(bodyBytes),
	}
	if err != nil {
		entry.body = fmt.Sprintf(`{"marshal_error":%q}`, err.Error())
	}
	if len(a.pipeHistory) >= pipeHistoryLimit {
		a.pipeHistory = append(a.pipeHistory[1:], entry)
	} else {
		a.pipeHistory = append(a.pipeHistory, entry)
	}
	if a.view == viewPipe {
		a.updateViewportContent()
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
