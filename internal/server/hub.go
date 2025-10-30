package server

import (
	"sync"

	"github.com/fenggwsx/SlashChat/internal/protocol"
)

// RoomHub tracks subscriptions and dispatches envelopes per room.
type RoomHub struct {
	mu     sync.RWMutex
	rooms  map[string]map[string]chan protocol.Envelope
	system chan protocol.Envelope
}

// NewRoomHub initializes an empty hub.
func NewRoomHub() *RoomHub {
	return &RoomHub{
		rooms:  make(map[string]map[string]chan protocol.Envelope),
		system: make(chan protocol.Envelope, 32),
	}
}

// Register registers a subscriber channel for the provided room.
func (h *RoomHub) Register(room string, sessionID string, ch chan protocol.Envelope) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if _, ok := h.rooms[room]; !ok {
		h.rooms[room] = make(map[string]chan protocol.Envelope)
	}
	h.rooms[room][sessionID] = ch
}

// Unregister removes the subscriber if present.
func (h *RoomHub) Unregister(room string, sessionID string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if subscribers, ok := h.rooms[room]; ok {
		delete(subscribers, sessionID)
		if len(subscribers) == 0 {
			delete(h.rooms, room)
		}
	}
}

// Broadcast pushes the envelope to every subscriber for its target room.
func (h *RoomHub) Broadcast(env protocol.Envelope) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	room := ""
	if env.Metadata != nil {
		if r, ok := env.Metadata["room"].(string); ok {
			room = r
		}
	}

	if room == "" {
		select {
		case h.system <- env:
		default:
		}
		return
	}

	for _, ch := range h.rooms[room] {
		select {
		case ch <- env:
		default:
		}
	}
}
