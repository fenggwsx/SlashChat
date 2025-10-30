package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"

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
	// Authentication handling will be implemented in subsequent iterations.
	ack := protocol.Envelope{
		ID:        uuid.NewString(),
		Type:      protocol.MessageTypeAck,
		Timestamp: time.Now(),
		Payload: protocol.AckPayload{
			ReferenceID: env.ID,
			Status:      "queued",
		},
	}
	if err := encoder.Encode(ctx, ack); err != nil {
		log.Printf("send ack: %v", err)
	}
}
