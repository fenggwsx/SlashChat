package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
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
}

// NewApp constructs a server instance using the provided dependencies.
func NewApp(cfg config.ServerConfig, store storage.Store) *App {
	return &App{
		cfg:   cfg,
		store: store,
		hub:   NewRoomHub(),
	}
}

// Run starts accepting connections until the context is canceled.
func (a *App) Run(ctx context.Context) error {
	if err := a.store.Migrate(ctx); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	listener, err := net.Listen("tcp", a.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	a.listener = listener

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
		history.Messages = append(history.Messages, protocol.ChatMessage{
			ID:        msg.ID,
			Room:      msg.Room,
			UserID:    msg.UserID,
			Username:  msg.Username,
			Content:   msg.Content,
			CreatedAt: msg.CreatedAt.Unix(),
		})
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
		ID:        uuid.NewString(),
		Room:      room,
		UserID:    claims.UserID,
		Username:  claims.Username,
		Content:   content,
		CreatedAt: now,
	}
	if err := a.store.SaveMessage(ctx, &msg); err != nil {
		a.sendAck(ctx, session, env.ID, ackStatusError, "message not stored")
		return err
	}

	a.sendAck(ctx, session, env.ID, ackStatusOK, "")

	broadcast := protocol.Envelope{
		ID:        uuid.NewString(),
		Type:      protocol.MessageTypeEvent,
		Timestamp: now,
		Metadata: map[string]interface{}{
			"action": "chat_message",
			"room":   room,
		},
		Payload: protocol.ChatMessage{
			ID:        msg.ID,
			Room:      msg.Room,
			UserID:    msg.UserID,
			Username:  msg.Username,
			Content:   msg.Content,
			CreatedAt: msg.CreatedAt.Unix(),
		},
	}
	a.hub.Broadcast(broadcast)
	return nil
}

func (a *App) handleRegister(ctx context.Context, session *clientSession, referenceID string, req protocol.AuthRequest) error {
	user, err := a.createUser(ctx, req)
	if err != nil {
		a.reportAuthError(ctx, session, referenceID, err)
		return nil
	}
	return a.issueToken(ctx, session, referenceID, user)
}

func (a *App) handleLogin(ctx context.Context, session *clientSession, referenceID string, req protocol.AuthRequest) error {
	user, err := a.authenticateUser(ctx, req)
	if err != nil {
		a.reportAuthError(ctx, session, referenceID, err)
		return nil
	}
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
		ID:        uuid.NewString(),
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
	ackStatusOK    = "ok"
	ackStatusError = "error"
)

var (
	errUserExists         = errors.New("user already exists")
	errInvalidCredentials = errors.New("invalid credentials")
	errInvalidPayload     = errors.New("invalid auth payload")
)
