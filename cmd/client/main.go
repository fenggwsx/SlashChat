package main

import (
	"log"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/fenggwsx/SlashChat/internal/client"
	"github.com/fenggwsx/SlashChat/internal/config"
)

func main() {
	cfg := config.LoadClientConfig()

	model := client.NewApp(cfg)

	if err := tea.NewProgram(model, tea.WithAltScreen()).Start(); err != nil {
		log.Fatalf("client exited: %v", err)
	}
}
