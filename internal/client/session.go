package client

import (
	"context"
	"net"
	"time"

	"github.com/google/uuid"

	"github.com/fenggwsx/SlashChat/internal/config"
	"github.com/fenggwsx/SlashChat/internal/protocol"
)

// Session manages client-side socket interactions with the GoSlash server.
type Session struct {
	cfg      config.ClientConfig
	conn     net.Conn
	encoder  *protocol.Encoder
	decoder  *protocol.Decoder
	cancelFn context.CancelFunc
}

// NewSession initializes a session with configuration.
func NewSession(cfg config.ClientConfig) *Session {
	return &Session{cfg: cfg}
}

// Connect dials the server and prepares framed JSON encoders/decoders.
func (s *Session) Connect(ctx context.Context) error {
	if s.cfg.ServerAddr == "" {
		return net.ErrClosed
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", s.cfg.ServerAddr)
	if err != nil {
		return err
	}
	s.conn = conn
	s.encoder = protocol.NewEncoder(conn)
	s.decoder = protocol.NewDecoder(conn)
	ctx, cancel := context.WithCancel(ctx)
	s.cancelFn = cancel
	go s.readLoop(ctx)
	return nil
}

// Close terminates the session.
func (s *Session) Close() error {
	if s.cancelFn != nil {
		s.cancelFn()
	}
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

// Send dispatches an envelope to the server.
func (s *Session) Send(ctx context.Context, env protocol.Envelope) error {
	if env.ID == "" {
		env.ID = uuid.NewString()
	}
	env.Timestamp = time.Now()
	return s.encoder.Encode(ctx, env)
}

func (s *Session) readLoop(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		_, err := s.decoder.Decode(ctx)
		if err != nil {
			return
		}
	}
}
