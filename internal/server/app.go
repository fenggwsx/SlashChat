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

	for {
		if deadlineErr := conn.SetReadDeadline(time.Now().Add(a.cfg.ReadTimeout)); deadlineErr != nil {
			log.Printf("set read deadline: %v", deadlineErr)
			return
		}
		env, err := decoder.Decode(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, io.EOF) {
				return
			}
			log.Printf("decode: %v", err)
			return
		}

		go a.routeEnvelope(ctx, encoder, env)
	}
}

func (a *App) routeEnvelope(ctx context.Context, encoder *protocol.Encoder, env protocol.Envelope) {
	switch env.Type {
	case protocol.MessageTypeAuthRequest:
		a.handleAuth(ctx, encoder, env)
	case protocol.MessageTypeCommand, protocol.MessageTypeEvent, protocol.MessageTypeFileChunk:
		a.hub.Broadcast(env)
	default:
		log.Printf("unhandled envelope type: %s", env.Type)
	}
}

func (a *App) handleAuth(ctx context.Context, encoder *protocol.Encoder, env protocol.Envelope) {
	req, err := decodeAuthRequest(env.Payload)
	if err != nil {
		a.sendAck(ctx, encoder, env.ID, ackStatusError, "invalid auth payload")
		return
	}

	action := strings.ToLower(strings.TrimSpace(req.Action))
	switch action {
	case "register":
		a.handleRegister(ctx, encoder, env.ID, req)
	case "login":
		a.handleLogin(ctx, encoder, env.ID, req)
	default:
		a.sendAck(ctx, encoder, env.ID, ackStatusError, "unsupported auth action")
	}
}

func (a *App) handleRegister(ctx context.Context, encoder *protocol.Encoder, referenceID string, req protocol.AuthRequest) {
	user, err := a.createUser(ctx, req)
	if err != nil {
		a.reportAuthError(ctx, encoder, referenceID, err)
		return
	}
	a.issueToken(ctx, encoder, referenceID, user)
}

func (a *App) handleLogin(ctx context.Context, encoder *protocol.Encoder, referenceID string, req protocol.AuthRequest) {
	user, err := a.authenticateUser(ctx, req)
	if err != nil {
		a.reportAuthError(ctx, encoder, referenceID, err)
		return
	}
	a.issueToken(ctx, encoder, referenceID, user)
}

func (a *App) issueToken(ctx context.Context, encoder *protocol.Encoder, referenceID string, user *storage.User) {
	expiresAt := time.Now().Add(a.cfg.JWT.Expiration)
	token, err := auth.NewToken(a.cfg.JWT, user.ID, user.Username)
	if err != nil {
		log.Printf("token issue: %v", err)
		a.sendAck(ctx, encoder, referenceID, ackStatusError, "token generation failed")
		return
	}

	a.sendAck(ctx, encoder, referenceID, ackStatusOK, "")

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
	if err := encoder.Encode(ctx, response); err != nil {
		log.Printf("auth response send: %v", err)
	}
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

func (a *App) reportAuthError(ctx context.Context, encoder *protocol.Encoder, referenceID string, err error) {
	reason := "authentication failed"
	switch {
	case errors.Is(err, errUserExists):
		reason = "username already exists"
	case errors.Is(err, errInvalidCredentials):
		reason = "invalid credentials"
	case errors.Is(err, errInvalidPayload):
		reason = "invalid credentials"
	}
	a.sendAck(ctx, encoder, referenceID, ackStatusError, reason)
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

func (a *App) sendAck(ctx context.Context, encoder *protocol.Encoder, referenceID, status, reason string) {
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
	if err := encoder.Encode(ctx, ack); err != nil {
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
