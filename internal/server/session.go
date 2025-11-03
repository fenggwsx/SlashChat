package server

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/fenggwsx/SlashChat/internal/protocol"
)

// clientSession tracks per-connection state and outbound delivery.
type clientSession struct {
	id       string
	app      *App
	conn     net.Conn
	sendCh   chan protocol.Envelope
	rooms    map[string]struct{}
	closeMux sync.Once
	mu       sync.Mutex
}

func newClientSession(app *App, conn net.Conn) *clientSession {
	return &clientSession{
		id:     uuid.NewString(),
		app:    app,
		conn:   conn,
		sendCh: make(chan protocol.Envelope, 64),
		rooms:  make(map[string]struct{}),
	}
}

func (s *clientSession) send(ctx context.Context, env protocol.Envelope) error {
	select {
	case s.sendCh <- env:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *clientSession) writeLoop(ctx context.Context, encoder *protocol.Encoder, writeTimeout time.Duration) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case env, ok := <-s.sendCh:
			if !ok {
				return nil
			}
			if s.conn != nil && writeTimeout > 0 {
				if err := s.conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
					return err
				}
			}
			if err := encoder.Encode(ctx, env); err != nil {
				return err
			}
		}
	}
}

func (s *clientSession) registerRoom(room string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.rooms[room]; ok {
		return
	}
	s.app.hub.Register(room, s.id, s.sendCh)
	s.rooms[room] = struct{}{}
}

func (s *clientSession) unregisterRoom(room string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.rooms[room]; !ok {
		return
	}
	s.app.hub.Unregister(room, s.id)
	delete(s.rooms, room)
}

func (s *clientSession) inRoom(room string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.rooms[room]
	return ok
}

func (s *clientSession) unregisterAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for room := range s.rooms {
		s.app.hub.Unregister(room, s.id)
		delete(s.rooms, room)
	}
}

func (s *clientSession) remoteAddr() string {
	if s.conn == nil {
		return ""
	}
	if addr := s.conn.RemoteAddr(); addr != nil {
		return addr.String()
	}
	return ""
}

func (s *clientSession) close() {
	s.closeMux.Do(func() {
		s.unregisterAll()
		close(s.sendCh)
	})
}
