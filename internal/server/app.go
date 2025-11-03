package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/fenggwsx/SlashChat/internal/auth"
	"github.com/fenggwsx/SlashChat/internal/config"
	"github.com/fenggwsx/SlashChat/internal/protocol"
	"github.com/fenggwsx/SlashChat/internal/storage"
)

// App coordinates network listeners, session lifecycle, and room routing.
type App struct {
	cfg       config.ServerConfig
	store     storage.Store
	hub       *RoomHub
	listener  net.Listener
	closeOnce sync.Once
	uploadDir string
}

const defaultUploadDir = "uploads"

// NewApp constructs a server instance using the provided dependencies.
func NewApp(cfg config.ServerConfig, store storage.Store) *App {
	dir := strings.TrimSpace(cfg.UploadDir)
	if dir == "" {
		dir = defaultUploadDir
	}
	return &App{
		cfg:       cfg,
		store:     store,
		hub:       NewRoomHub(),
		uploadDir: dir,
	}
}

// Run starts accepting connections until the context is canceled.
func (a *App) Run(ctx context.Context) error {
	if err := a.store.Migrate(ctx); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	if _, err := a.ensureUploadsDir(); err != nil {
		return fmt.Errorf("uploads dir: %w", err)
	}

	listener, err := net.Listen("tcp", a.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	a.listener = listener
	log.Printf("server listening on %s", listener.Addr().String())

	errCh := make(chan error, 1)

	go func() {
		<-ctx.Done()
		a.closeOnce.Do(func() {
			_ = a.listener.Close()
		})
	}()

	go func() {
		for {
			conn, err := a.listener.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					errCh <- nil
					return
				}
				errCh <- err
				return
			}
			go a.handleConnection(ctx, conn)
		}
	}()

	return <-errCh
}

func (a *App) handleConnection(parentCtx context.Context, conn net.Conn) {
	defer conn.Close()

	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	decoder := protocol.NewDecoder(conn)
	encoder := protocol.NewEncoder(conn)
	session := newClientSession(a, conn)
	log.Printf("client connected remote=%s session=%s", session.remoteAddr(), session.id)
	defer log.Printf("client disconnected remote=%s session=%s", session.remoteAddr(), session.id)

	go func() {
		if err := session.writeLoop(ctx, encoder, a.cfg.WriteTimeout); err != nil && !errors.Is(err, context.Canceled) {
			if !errors.Is(err, net.ErrClosed) {
				log.Printf("write loop: %v", err)
			}
		}
		cancel()
	}()
	defer session.close()

	for {
		if err := conn.SetReadDeadline(time.Now().Add(a.cfg.ReadTimeout)); err != nil {
			log.Printf("set read deadline: %v", err)
			return
		}

		env, err := decoder.Decode(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("decode: %v", err)
			return
		}

		if err := a.routeEnvelope(ctx, session, env); err != nil {
			log.Printf("route envelope: %v", err)
			return
		}
	}
}

func (a *App) routeEnvelope(ctx context.Context, session *clientSession, env protocol.Envelope) error {
	switch env.Type {
	case protocol.MessageTypeAuthRequest:
		return a.handleAuth(ctx, session, env)
	case protocol.MessageTypeAck:
		// Ignore client-generated heartbeats.
		return nil
	case protocol.MessageTypeCommand:
		return a.handleCommand(ctx, session, env)
	case protocol.MessageTypeEvent:
		return a.handleEvent(ctx, session, env)
	case protocol.MessageTypeFileChunk:
		// File handling not yet implemented.
		return nil
	case protocol.MessageTypeFileUpload:
		return a.handleFileUploadData(ctx, session, env)
	default:
		log.Printf("unhandled envelope type: %s", env.Type)
	}
	return nil
}

func (a *App) handleAuth(ctx context.Context, session *clientSession, env protocol.Envelope) error {
	req, err := decodeAuthRequest(env.Payload)
	if err != nil {
		a.sendAck(ctx, session, env.ID, ackStatusError, "invalid auth payload")
		return nil
	}

	action := strings.ToLower(strings.TrimSpace(req.Action))
	switch action {
	case "register":
		return a.handleRegister(ctx, session, env.ID, req)
	case "login":
		return a.handleLogin(ctx, session, env.ID, req)
	default:
		a.sendAck(ctx, session, env.ID, ackStatusError, "unsupported auth action")
	}
	return nil
}

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

	a.sendAck(ctx, session, env.ID, ackStatusOK, "")

	response := protocol.Envelope{
		ID:        uuid.NewString(),
		Type:      protocol.MessageTypeFileDownload,
		Timestamp: time.Now(),
		Metadata: map[string]interface{}{
			"action":     "file_download",
			"message_id": fmt.Sprintf("%d", msg.ID),
		},
		Payload: protocol.FileDownloadPayload{
			MessageID:  msg.ID,
			Filename:   filename,
			SHA256:     sha,
			DataBase64: encoded,
		},
	}

	if err := session.send(ctx, response); err != nil {
		return err
	}
	log.Printf("file download served message_id=%d room=%s requester=%s remote=%s size=%dB", msg.ID, msg.Room, claims.Username, session.remoteAddr(), len(data))
	return nil
}

func (a *App) handleRegister(ctx context.Context, session *clientSession, referenceID string, req protocol.AuthRequest) error {
	username := strings.TrimSpace(req.Username)
	user, err := a.createUser(ctx, req)
	if err != nil {
		log.Printf("register failed user=%s remote=%s err=%v", username, session.remoteAddr(), err)
		a.reportAuthError(ctx, session, referenceID, err)
		return nil
	}
	log.Printf("register success user=%s id=%d remote=%s", user.Username, user.ID, session.remoteAddr())
	return a.issueToken(ctx, session, referenceID, user)
}

func (a *App) handleLogin(ctx context.Context, session *clientSession, referenceID string, req protocol.AuthRequest) error {
	username := strings.TrimSpace(req.Username)
	user, err := a.authenticateUser(ctx, req)
	if err != nil {
		log.Printf("login failed user=%s remote=%s err=%v", username, session.remoteAddr(), err)
		a.reportAuthError(ctx, session, referenceID, err)
		return nil
	}
	log.Printf("login success user=%s id=%d remote=%s", user.Username, user.ID, session.remoteAddr())
	return a.issueToken(ctx, session, referenceID, user)
}

func (a *App) issueToken(ctx context.Context, session *clientSession, referenceID string, user *storage.User) error {
	expiresAt := time.Now().Add(a.cfg.JWT.Expiration)
	token, err := auth.NewToken(a.cfg.JWT, user.ID, user.Username)
	if err != nil {
		log.Printf("token issue: %v", err)
		a.sendAck(ctx, session, referenceID, ackStatusError, "token generation failed")
		return err
	}

	a.sendAck(ctx, session, referenceID, ackStatusOK, "")

	response := protocol.Envelope{
		ID:        uuid.NewString(),
		Type:      protocol.MessageTypeAuthResponse,
		Timestamp: time.Now(),
		Payload: protocol.AuthResponse{
			Token:     token,
			ExpiresAt: expiresAt.Unix(),
			UserID:    user.ID,
		},
	}
	if err := session.send(ctx, response); err != nil {
		return err
	}
	return nil
}

func (a *App) createUser(ctx context.Context, req protocol.AuthRequest) (*storage.User, error) {
	username, password, err := sanitizeCredentials(req)
	if err != nil {
		return nil, err
	}

	if _, err := a.store.GetUserByUsername(ctx, username); err == nil {
		return nil, errUserExists
	} else if !errors.Is(err, storage.ErrNotFound) {
		return nil, err
	}

	hashed, err := auth.HashPassword(password)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	user := &storage.User{
		Username:  username,
		Password:  hashed,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := a.store.CreateUser(ctx, user); err != nil {
		return nil, err
	}

	return user, nil
}

func (a *App) authenticateUser(ctx context.Context, req protocol.AuthRequest) (*storage.User, error) {
	username, password, err := sanitizeCredentials(req)
	if err != nil {
		return nil, err
	}

	user, err := a.store.GetUserByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, errInvalidCredentials
		}
		return nil, err
	}

	if err := auth.ComparePassword(user.Password, password); err != nil {
		return nil, errInvalidCredentials
	}

	return user, nil
}

func (a *App) reportAuthError(ctx context.Context, session *clientSession, referenceID string, err error) {
	reason := "authentication failed"
	switch {
	case errors.Is(err, errUserExists):
		reason = "username already exists"
	case errors.Is(err, errInvalidCredentials):
		reason = "invalid credentials"
	case errors.Is(err, errInvalidPayload):
		reason = "invalid credentials"
	}
	a.sendAck(ctx, session, referenceID, ackStatusError, reason)
}

func sanitizeCredentials(req protocol.AuthRequest) (string, string, error) {
	username := strings.TrimSpace(req.Username)
	password := req.Password
	if username == "" || password == "" {
		return "", "", errInvalidPayload
	}
	return username, password, nil
}

func decodeAuthRequest(payload interface{}) (protocol.AuthRequest, error) {
	var req protocol.AuthRequest
	if payload == nil {
		return req, errInvalidPayload
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return req, err
	}
	if err := json.Unmarshal(data, &req); err != nil {
		return req, err
	}
	return req, nil
}

func decodeJoinRequest(payload interface{}) (protocol.JoinRequest, error) {
	var req protocol.JoinRequest
	if payload == nil {
		return req, errInvalidPayload
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return req, err
	}
	if err := json.Unmarshal(data, &req); err != nil {
		return req, err
	}
	return req, nil
}

func decodeLeaveRequest(payload interface{}) (protocol.LeaveRequest, error) {
	var req protocol.LeaveRequest
	if payload == nil {
		return req, errInvalidPayload
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return req, err
	}
	if err := json.Unmarshal(data, &req); err != nil {
		return req, err
	}
	return req, nil
}

func decodeChatSendRequest(payload interface{}) (protocol.ChatSendRequest, error) {
	var req protocol.ChatSendRequest
	if payload == nil {
		return req, errInvalidPayload
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return req, err
	}
	if err := json.Unmarshal(data, &req); err != nil {
		return req, err
	}
	return req, nil
}

func decodeFileUploadRequest(payload interface{}) (protocol.FileUploadRequest, error) {
	var req protocol.FileUploadRequest
	if payload == nil {
		return req, errInvalidPayload
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return req, err
	}
	if err := json.Unmarshal(data, &req); err != nil {
		return req, err
	}
	return req, nil
}

func decodeFileUploadPayload(payload interface{}) (protocol.FileUploadPayload, error) {
	var req protocol.FileUploadPayload
	if payload == nil {
		return req, errInvalidPayload
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return req, err
	}
	if err := json.Unmarshal(data, &req); err != nil {
		return req, err
	}
	return req, nil
}

func decodeFileDownloadRequest(payload interface{}) (protocol.FileDownloadRequest, error) {
	var req protocol.FileDownloadRequest
	if payload == nil {
		return req, errInvalidPayload
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return req, err
	}
	if err := json.Unmarshal(data, &req); err != nil {
		return req, err
	}
	return req, nil
}

func (a *App) claimsFromEnvelope(env protocol.Envelope) (*auth.Claims, error) {
	token := strings.TrimSpace(env.Token)
	if token == "" {
		return nil, fmt.Errorf("missing token")
	}
	return auth.ParseToken(a.cfg.JWT, token)
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

func (a *App) sendAck(ctx context.Context, session *clientSession, referenceID, status, reason string) {
	ack := protocol.Envelope{
		ID:        uuid.NewString(),
		Type:      protocol.MessageTypeAck,
		Timestamp: time.Now(),
		Payload: protocol.AckPayload{
			ReferenceID: referenceID,
			Status:      status,
			Reason:      reason,
		},
	}
	if err := session.send(ctx, ack); err != nil {
		log.Printf("send ack: %v", err)
	}
}

const (
	ackStatusOK             = "ok"
	ackStatusError          = "error"
	ackStatusUploadRequired = "upload_required"
)

var (
	errUserExists         = errors.New("user already exists")
	errInvalidCredentials = errors.New("invalid credentials")
	errInvalidPayload     = errors.New("invalid auth payload")
)
