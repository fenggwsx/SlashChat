package storage

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound indicates that the requested record could not be located.
var ErrNotFound = errors.New("storage: not found")

// User represents a persisted account record.
type User struct {
	ID        string
	Username  string
	Password  string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Store defines persistence operations used by the server.
type Store interface {
	Close() error
	Migrate(ctx context.Context) error

	CreateUser(ctx context.Context, user *User) error
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	SaveMessage(ctx context.Context, msg *Message) error
	ListMessagesByRoom(ctx context.Context, room string, limit int) ([]Message, error)
}

// Message represents a persisted chat message entry.
type Message struct {
	ID        string
	Room      string
	UserID    string
	Username  string
	Content   string
	CreatedAt time.Time
}
