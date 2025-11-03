package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

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
