package storage

import (
	"context"
	"time"
)

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
}
