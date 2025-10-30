package sqlite

import (
	"context"
	"errors"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/fenggwsx/SlashChat/internal/config"
	"github.com/fenggwsx/SlashChat/internal/storage"
)

// Store is a GORM-backed SQLite implementation of storage.Store.
type Store struct {
	db *gorm.DB
}

type userModel struct {
	ID        string `gorm:"primaryKey"`
	Username  string `gorm:"uniqueIndex"`
	Password  string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// NewStore opens a SQLite database at the provided path.
func NewStore(cfg config.DatabaseConfig) (*Store, error) {
	db, err := gorm.Open(sqlite.Open(cfg.Path), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close releases the underlying database connection.
func (s *Store) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// Migrate applies schema updates.
func (s *Store) Migrate(ctx context.Context) error {
	return s.db.WithContext(ctx).AutoMigrate(&userModel{})
}

// CreateUser stores a new user record.
func (s *Store) CreateUser(ctx context.Context, user *storage.User) error {
	if user == nil {
		return errors.New("nil user")
	}
	model := userModel{
		ID:        user.ID,
		Username:  user.Username,
		Password:  user.Password,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}
	return s.db.WithContext(ctx).Create(&model).Error
}

// GetUserByUsername retrieves a user by username.
func (s *Store) GetUserByUsername(ctx context.Context, username string) (*storage.User, error) {
	var model userModel
	if err := s.db.WithContext(ctx).Where("username = ?", username).First(&model).Error; err != nil {
		return nil, err
	}
	user := &storage.User{
		ID:        model.ID,
		Username:  model.Username,
		Password:  model.Password,
		CreatedAt: model.CreatedAt,
		UpdatedAt: model.UpdatedAt,
	}
	return user, nil
}
