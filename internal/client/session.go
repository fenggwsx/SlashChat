package client

import (
	"context"
	"errors"
	"net"
	"sync"
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
	incoming chan protocol.Envelope
	mu       sync.Mutex
}

// NewSession initializes a session with configuration.
func NewSession(cfg config.ClientConfig) *Session {
	return &Session{
		cfg:      cfg,
		incoming: make(chan protocol.Envelope, 32),
	}
}

const (
	heartbeatInterval = 10 * time.Second
	heartbeatTimeout  = 3 * time.Second
)

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
	loopCtx, cancel := context.WithCancel(context.Background())
	s.cancelFn = cancel
	go s.readLoop(loopCtx)
	go s.heartbeatLoop(loopCtx)
	return nil
}

// Close terminates the session.
func (s *Session) Close() error {
	if s.cancelFn != nil {
		s.cancelFn()
	}
	var err error
	if s.conn != nil {
		err = s.conn.Close()
	}
	s.mu.Lock()
	s.encoder = nil
	s.decoder = nil
	s.conn = nil
	s.mu.Unlock()
	return err
}

// Send dispatches an envelope to the server.
func (s *Session) Send(ctx context.Context, env protocol.Envelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.encoder == nil {
		return errors.New("session not connected")
	}
	if env.ID == "" {
		env.ID = uuid.NewString()
	}
	env.Timestamp = time.Now()
	return s.encoder.Encode(ctx, env)
}

func (s *Session) readLoop(ctx context.Context) {
	defer close(s.incoming)
	for {
		if ctx.Err() != nil {
			return
		}
		env, err := s.decoder.Decode(ctx)
		if err != nil {
			return
		}
		select {
		case s.incoming <- env:
		default:
		}
	}
}

func (s *Session) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sendHeartbeat()
		}
	}
}

func (s *Session) sendHeartbeat() {
	ctx, cancel := context.WithTimeout(context.Background(), heartbeatTimeout)
	defer cancel()
	_ = s.Send(ctx, protocol.Envelope{
		Type: protocol.MessageTypeAck,
		Payload: protocol.AckPayload{
			ReferenceID: "heartbeat",
			Status:      "ok",
		},
		Metadata: map[string]interface{}{
			"purpose": "keepalive",
		},
	})
}

// Messages returns a read-only channel for inbound envelopes.
func (s *Session) Messages() <-chan protocol.Envelope {
	return s.incoming
}
