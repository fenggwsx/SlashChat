package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fenggwsx/SlashChat/internal/auth"
	"github.com/fenggwsx/SlashChat/internal/protocol"
	"github.com/fenggwsx/SlashChat/internal/storage"
)

var (
	errUserExists         = errors.New("user already exists")
	errInvalidCredentials = errors.New("invalid credentials")
	errInvalidPayload     = errors.New("invalid auth payload")
)

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

func (a *App) claimsFromEnvelope(env protocol.Envelope) (*auth.Claims, error) {
	token := strings.TrimSpace(env.Token)
	if token == "" {
		return nil, fmt.Errorf("missing token")
	}
	return auth.ParseToken(a.cfg.JWT, token)
}
