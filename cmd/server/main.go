package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	"github.com/fenggwsx/SlashChat/internal/config"
	"github.com/fenggwsx/SlashChat/internal/server"
	"github.com/fenggwsx/SlashChat/internal/storage/sqlite"
)

func main() {
	cfg := config.LoadServerConfig()

	store, err := sqlite.NewStore(cfg.Database)
	if err != nil {
		log.Fatalf("init storage: %v", err)
	}
	defer store.Close()

	app := server.NewApp(cfg, store)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := app.Run(ctx); err != nil {
		log.Fatalf("server shutdown: %v", err)
	}
}
