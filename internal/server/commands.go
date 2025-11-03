package server

import (
	"context"
	"encoding/base64"
	"errors"
	"log"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fenggwsx/SlashChat/internal/protocol"
	"github.com/fenggwsx/SlashChat/internal/storage"
)

func (a *App) handleCommand(ctx context.Context, session *clientSession, env protocol.Envelope) error {
	action := strings.ToLower(strings.TrimSpace(metadataString(env.Metadata, "action")))
	switch action {
	case "join":
		return a.handleJoinCommand(ctx, session, env)
	case "leave":
		return a.handleLeaveCommand(ctx, session, env)
	case "file_upload_prepare":
		return a.handleFileUploadPrepare(ctx, session, env)
	case "file_download":
		return a.handleFileDownloadCommand(ctx, session, env)
	default:
		a.sendAck(ctx, session, env.ID, ackStatusError, "unsupported command")
	}
	return nil
}

func (a *App) handleEvent(ctx context.Context, session *clientSession, env protocol.Envelope) error {
	action := strings.ToLower(strings.TrimSpace(metadataString(env.Metadata, "action")))
	switch action {
	case "chat_send":
		return a.handleChatSend(ctx, session, env)
	default:
		return nil
	}
}

func (a *App) handleJoinCommand(ctx context.Context, session *clientSession, env protocol.Envelope) error {
	claims, err := a.claimsFromEnvelope(env)
	if err != nil {
		a.sendAck(ctx, session, env.ID, ackStatusError, "unauthorized")
		return nil
	}

	req, err := decodeJoinRequest(env.Payload)
	if err != nil {
		a.sendAck(ctx, session, env.ID, ackStatusError, "invalid join payload")
		return nil
	}

	room := strings.TrimSpace(req.Room)
	if room == "" {
		a.sendAck(ctx, session, env.ID, ackStatusError, "room required")
		return nil
	}

	messages, err := a.store.ListMessagesByRoom(ctx, room, 100)
	if err != nil {
		a.sendAck(ctx, session, env.ID, ackStatusError, "history unavailable")
		return err
	}

	session.registerRoom(room)
	a.sendAck(ctx, session, env.ID, ackStatusOK, "")

	history := protocol.ChatHistory{Room: room, Messages: make([]protocol.ChatMessage, 0, len(messages))}
	for _, msg := range messages {
		history.Messages = append(history.Messages, toProtocolChatMessage(msg))
	}

	event := protocol.Envelope{
		ID:        uuid.NewString(),
		Type:      protocol.MessageTypeEvent,
		Timestamp: time.Now(),
		Metadata: map[string]interface{}{
			"action": "chat_history",
			"room":   room,
			"user":   claims.Username,
		},
		Payload: history,
	}
	return session.send(ctx, event)
}

func (a *App) handleLeaveCommand(ctx context.Context, session *clientSession, env protocol.Envelope) error {
	if _, err := a.claimsFromEnvelope(env); err != nil {
		a.sendAck(ctx, session, env.ID, ackStatusError, "unauthorized")
		return nil
	}
	req, err := decodeLeaveRequest(env.Payload)
	if err != nil {
		a.sendAck(ctx, session, env.ID, ackStatusError, "invalid leave payload")
		return nil
	}
	room := strings.TrimSpace(req.Room)
	if room == "" {
		a.sendAck(ctx, session, env.ID, ackStatusError, "room required")
		return nil
	}
	session.unregisterRoom(room)
	a.sendAck(ctx, session, env.ID, ackStatusOK, "")
	return nil
}

func (a *App) handleChatSend(ctx context.Context, session *clientSession, env protocol.Envelope) error {
	claims, err := a.claimsFromEnvelope(env)
	if err != nil {
		a.sendAck(ctx, session, env.ID, ackStatusError, "unauthorized")
		return nil
	}
	req, err := decodeChatSendRequest(env.Payload)
	if err != nil {
		a.sendAck(ctx, session, env.ID, ackStatusError, "invalid message payload")
		return nil
	}
	room := strings.TrimSpace(req.Room)
	if room == "" {
		a.sendAck(ctx, session, env.ID, ackStatusError, "room required")
		return nil
	}
	if !session.inRoom(room) {
		a.sendAck(ctx, session, env.ID, ackStatusError, "join room first")
		return nil
	}
	content := strings.TrimSpace(req.Content)
	if content == "" {
		a.sendAck(ctx, session, env.ID, ackStatusError, "message empty")
		return nil
	}

	now := time.Now().UTC()
	msg := storage.Message{
		Room:      room,
		UserID:    claims.UserID,
		Content:   content,
		Kind:      string(protocol.MessageKindText),
		CreatedAt: now,
		User: &storage.User{
			ID:       claims.UserID,
			Username: claims.Username,
		},
	}
	if err := a.store.SaveMessage(ctx, &msg); err != nil {
		a.sendAck(ctx, session, env.ID, ackStatusError, "message not stored")
		return err
	}

	a.sendAck(ctx, session, env.ID, ackStatusOK, "")
	log.Printf("chat message stored id=%d room=%s user=%s len=%d remote=%s", msg.ID, msg.Room, claims.Username, len(content), session.remoteAddr())

	a.broadcastChatMessage(msg)
	return nil
}

func (a *App) handleFileDownloadCommand(ctx context.Context, session *clientSession, env protocol.Envelope) error {
	claims, err := a.claimsFromEnvelope(env)
	if err != nil {
		a.sendAck(ctx, session, env.ID, ackStatusError, "unauthorized")
		return nil
	}

	req, err := decodeFileDownloadRequest(env.Payload)
	if err != nil {
		a.sendAck(ctx, session, env.ID, ackStatusError, "invalid download payload")
		return nil
	}

	if req.MessageID == 0 {
		a.sendAck(ctx, session, env.ID, ackStatusError, "message id required")
		return nil
	}

	msg, err := a.store.GetMessageByID(ctx, req.MessageID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			a.sendAck(ctx, session, env.ID, ackStatusError, "message not found")
			return nil
		}
		a.sendAck(ctx, session, env.ID, ackStatusError, "message lookup failed")
		return err
	}

	if strings.ToLower(strings.TrimSpace(msg.Kind)) != string(protocol.MessageKindFile) {
		a.sendAck(ctx, session, env.ID, ackStatusError, "not a file message")
		return nil
	}

	if !session.inRoom(msg.Room) {
		a.sendAck(ctx, session, env.ID, ackStatusError, "join room first")
		return nil
	}

	sha := normalizeSHA(msg.FileSHA)
	if sha == "" {
		a.sendAck(ctx, session, env.ID, ackStatusError, "file missing")
		return nil
	}

	path, err := a.uploadFilePath(sha)
	if err != nil {
		a.sendAck(ctx, session, env.ID, ackStatusError, "file path error")
		return err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			a.sendAck(ctx, session, env.ID, ackStatusError, "file missing")
			return nil
		}
		a.sendAck(ctx, session, env.ID, ackStatusError, "file read failed")
		return err
	}

	encoded := base64.StdEncoding.EncodeToString(data)
	filename := strings.TrimSpace(msg.Content)
	if filename == "" {
		filename = sha
	}

	payload := protocol.FileDownloadPayload{
		MessageID:  msg.ID,
		Filename:   filename,
		SHA256:     sha,
		DataBase64: encoded,
	}

	event := protocol.Envelope{
		ID:        uuid.NewString(),
		Type:      protocol.MessageTypeFileDownload,
		Timestamp: time.Now(),
		Metadata: map[string]interface{}{
			"action":     "file_download",
			"message_id": msg.ID,
			"user":       claims.Username,
		},
		Payload: payload,
	}
	if err := session.send(ctx, event); err != nil {
		return err
	}
	a.sendAck(ctx, session, env.ID, ackStatusOK, "")
	return nil
}
