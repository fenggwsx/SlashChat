package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fenggwsx/SlashChat/internal/auth"
	"github.com/fenggwsx/SlashChat/internal/protocol"
	"github.com/fenggwsx/SlashChat/internal/storage"
)

func (a *App) persistFileMessage(ctx context.Context, claims *auth.Claims, room, filename, sha string) (storage.Message, error) {
	now := time.Now().UTC()
	msg := storage.Message{
		Room:      room,
		UserID:    claims.UserID,
		Content:   strings.TrimSpace(filename),
		Kind:      string(protocol.MessageKindFile),
		FileSHA:   sha,
		CreatedAt: now,
		User: &storage.User{
			ID:       claims.UserID,
			Username: claims.Username,
		},
	}
	if err := a.store.SaveMessage(ctx, &msg); err != nil {
		return storage.Message{}, err
	}
	return msg, nil
}

func (a *App) broadcastChatMessage(msg storage.Message) {
	payload := toProtocolChatMessage(msg)
	timestamp := msg.CreatedAt
	if timestamp.IsZero() {
		timestamp = time.Now()
	}
	event := protocol.Envelope{
		ID:        uuid.NewString(),
		Type:      protocol.MessageTypeEvent,
		Timestamp: timestamp,
		Metadata: map[string]interface{}{
			"action": "chat_message",
			"room":   msg.Room,
		},
		Payload: payload,
	}
	a.hub.Broadcast(event)
}

func (a *App) writeFileIfMissing(sha string, data []byte) error {
	path, err := a.uploadFilePath(sha)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func (a *App) fileExists(sha string) bool {
	path, err := a.uploadFilePath(sha)
	if err != nil {
		return false
	}
	if _, err := os.Stat(path); err == nil {
		return true
	}
	return false
}

func (a *App) uploadFilePath(sha string) (string, error) {
	dir, err := a.ensureUploadsDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, sha), nil
}

func (a *App) ensureUploadsDir() (string, error) {
	dir := strings.TrimSpace(a.uploadDir)
	if dir == "" {
		dir = defaultUploadDir
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

func normalizeSHA(sha string) string {
	return strings.ToLower(strings.TrimSpace(sha))
}

func toProtocolChatMessage(msg storage.Message) protocol.ChatMessage {
	kind := toProtocolKind(msg.Kind)
	username := ""
	if msg.User != nil {
		username = msg.User.Username
	}
	filename := ""
	if kind == protocol.MessageKindFile {
		filename = msg.Content
	}
	return protocol.ChatMessage{
		ID:        msg.ID,
		Room:      msg.Room,
		UserID:    msg.UserID,
		Username:  username,
		Content:   msg.Content,
		Kind:      kind,
		Filename:  filename,
		SHA256:    msg.FileSHA,
		CreatedAt: msg.CreatedAt.Unix(),
	}
}

func toProtocolKind(kind string) protocol.MessageKind {
	switch protocol.MessageKind(strings.TrimSpace(kind)) {
	case protocol.MessageKindFile:
		return protocol.MessageKindFile
	default:
		return protocol.MessageKindText
	}
}

func (a *App) handleFileUploadPrepare(ctx context.Context, session *clientSession, env protocol.Envelope) error {
	claims, err := a.claimsFromEnvelope(env)
	if err != nil {
		a.sendAck(ctx, session, env.ID, ackStatusError, "unauthorized")
		return nil
	}
	req, err := decodeFileUploadRequest(env.Payload)
	if err != nil {
		a.sendAck(ctx, session, env.ID, ackStatusError, "invalid upload payload")
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
	filename := strings.TrimSpace(req.Filename)
	if filename == "" {
		a.sendAck(ctx, session, env.ID, ackStatusError, "filename required")
		return nil
	}
	sha := normalizeSHA(req.SHA256)
	if sha == "" {
		a.sendAck(ctx, session, env.ID, ackStatusError, "sha256 required")
		return nil
	}

	if !a.fileExists(sha) {
		a.sendAck(ctx, session, env.ID, ackStatusUploadRequired, "upload required")
		return nil
	}

	msg, err := a.persistFileMessage(ctx, claims, room, filename, sha)
	if err != nil {
		a.sendAck(ctx, session, env.ID, ackStatusError, "message not stored")
		return err
	}

	a.sendAck(ctx, session, env.ID, ackStatusOK, "")
	log.Printf("file message stored id=%d room=%s user=%s filename=%s remote=%s upload=skipped", msg.ID, msg.Room, claims.Username, filename, session.remoteAddr())
	a.broadcastChatMessage(msg)
	return nil
}

func (a *App) handleFileUploadData(ctx context.Context, session *clientSession, env protocol.Envelope) error {
	claims, err := a.claimsFromEnvelope(env)
	if err != nil {
		a.sendAck(ctx, session, env.ID, ackStatusError, "unauthorized")
		return nil
	}
	payload, err := decodeFileUploadPayload(env.Payload)
	if err != nil {
		a.sendAck(ctx, session, env.ID, ackStatusError, "invalid upload payload")
		return nil
	}

	room := strings.TrimSpace(payload.Room)
	if room == "" {
		a.sendAck(ctx, session, env.ID, ackStatusError, "room required")
		return nil
	}
	if !session.inRoom(room) {
		a.sendAck(ctx, session, env.ID, ackStatusError, "join room first")
		return nil
	}

	filename := strings.TrimSpace(payload.Filename)
	if filename == "" {
		a.sendAck(ctx, session, env.ID, ackStatusError, "filename required")
		return nil
	}

	sha := normalizeSHA(payload.SHA256)
	if sha == "" {
		a.sendAck(ctx, session, env.ID, ackStatusError, "sha256 required")
		return nil
	}

	data, err := base64.StdEncoding.DecodeString(payload.DataBase64)
	if err != nil {
		a.sendAck(ctx, session, env.ID, ackStatusError, "invalid data encoding")
		return nil
	}

	sum := sha256.Sum256(data)
	computed := fmt.Sprintf("%x", sum[:])
	if !strings.EqualFold(computed, sha) {
		a.sendAck(ctx, session, env.ID, ackStatusError, "sha256 mismatch")
		return nil
	}

	if err := a.writeFileIfMissing(computed, data); err != nil {
		a.sendAck(ctx, session, env.ID, ackStatusError, "upload failed")
		return err
	}

	msg, err := a.persistFileMessage(ctx, claims, room, filename, computed)
	if err != nil {
		a.sendAck(ctx, session, env.ID, ackStatusError, "message not stored")
		return err
	}

	a.sendAck(ctx, session, env.ID, ackStatusOK, "")
	log.Printf("file message stored id=%d room=%s user=%s filename=%s size=%dB remote=%s upload=completed", msg.ID, msg.Room, claims.Username, filename, len(data), session.remoteAddr())
	a.broadcastChatMessage(msg)
	return nil
}
