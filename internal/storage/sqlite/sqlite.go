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

type messageModel struct {
	ID        string `gorm:"primaryKey"`
	Room      string `gorm:"index"`
	UserID    string
	Username  string
	Content   string
	CreatedAt time.Time `gorm:"index"`
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
	return s.db.WithContext(ctx).AutoMigrate(&userModel{}, &messageModel{})
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
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, storage.ErrNotFound
		}
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

// SaveMessage persists a chat message entry.
func (s *Store) SaveMessage(ctx context.Context, msg *storage.Message) error {
	if msg == nil {
		return errors.New("nil message")
	}
	model := messageModel{
		ID:        msg.ID,
		Room:      msg.Room,
		UserID:    msg.UserID,
		Username:  msg.Username,
		Content:   msg.Content,
		CreatedAt: msg.CreatedAt,
	}
	return s.db.WithContext(ctx).Create(&model).Error
}

// ListMessagesByRoom returns the most recent messages for the specified room.
func (s *Store) ListMessagesByRoom(ctx context.Context, room string, limit int) ([]storage.Message, error) {
	if limit <= 0 {
		limit = 50
	}
	var models []messageModel
	if err := s.db.WithContext(ctx).Where("room = ?", room).Order("created_at desc").Limit(limit).Find(&models).Error; err != nil {
		return nil, err
	}
	// Reverse to chronological order ascending
	result := make([]storage.Message, len(models))
	for i := range models {
		model := models[i]
		result[len(models)-1-i] = storage.Message{
			ID:        model.ID,
			Room:      model.Room,
			UserID:    model.UserID,
			Username:  model.Username,
			Content:   model.Content,
			CreatedAt: model.CreatedAt,
		}
	}
	return result, nil
}
