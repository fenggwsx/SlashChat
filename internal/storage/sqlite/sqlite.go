package sqlite

import (
	"context"
	"errors"
	"log"
	"os"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/fenggwsx/SlashChat/internal/config"
	"github.com/fenggwsx/SlashChat/internal/storage"
)

// Store is a GORM-backed SQLite implementation of storage.Store.
type Store struct {
	db *gorm.DB
}

type User struct {
	ID        uint      `gorm:"primaryKey;autoIncrement"`
	Username  string    `gorm:"uniqueIndex;not null"`
	Password  string    `gorm:"not null"`
	CreatedAt time.Time `gorm:"not null"`
	UpdatedAt time.Time `gorm:"not null"`
}

type Message struct {
	ID        uint      `gorm:"primaryKey;autoIncrement"`
	Room      string    `gorm:"index;not null"`
	UserID    uint      `gorm:"not null"`
	Content   string    `gorm:"not null;default:''"`
	Kind      string    `gorm:"not null;default:text"`
	FileSHA   string    `gorm:"index;not null"`
	CreatedAt time.Time `gorm:"index;not null"`
	User      *User     `gorm:"foreignKey:UserID"`
}

// NewStore opens a SQLite database at the provided path.
func NewStore(cfg config.DatabaseConfig) (*Store, error) {
	gormLogger := logger.New(
		log.New(os.Stdout, "", log.LstdFlags),
		logger.Config{
			SlowThreshold:             time.Second,
			LogLevel:                  logger.Warn,
			IgnoreRecordNotFoundError: true,
		},
	)
	db, err := gorm.Open(sqlite.Open(cfg.Path), &gorm.Config{
		Logger: gormLogger,
	})
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
	return s.db.WithContext(ctx).AutoMigrate(&User{}, &Message{})
}

// CreateUser stores a new user record.
func (s *Store) CreateUser(ctx context.Context, user *storage.User) error {
	if user == nil {
		return errors.New("nil user")
	}
	model := User{
		Username:  user.Username,
		Password:  user.Password,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}
	if err := s.db.WithContext(ctx).Create(&model).Error; err != nil {
		return err
	}
	user.ID = model.ID
	return nil
}

// GetUserByUsername retrieves a user by username.
func (s *Store) GetUserByUsername(ctx context.Context, username string) (*storage.User, error) {
	var model User
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
	model := Message{
		Room:      msg.Room,
		UserID:    msg.UserID,
		Content:   msg.Content,
		Kind:      msg.Kind,
		FileSHA:   msg.FileSHA,
		CreatedAt: msg.CreatedAt,
	}
	if err := s.db.WithContext(ctx).Create(&model).Error; err != nil {
		return err
	}
	msg.ID = model.ID
	return nil
}

// ListMessagesByRoom returns the most recent messages for the specified room.
func (s *Store) ListMessagesByRoom(ctx context.Context, room string, limit int) ([]storage.Message, error) {
	if limit <= 0 {
		limit = 50
	}
	var models []Message
	if err := s.db.WithContext(ctx).
		Where("room = ?", room).
		Preload("User").
		Order("created_at desc").
		Limit(limit).
		Find(&models).Error; err != nil {
		return nil, err
	}
	// Reverse to chronological order ascending
	result := make([]storage.Message, len(models))
	for i := range models {
		model := models[i]
		var userPtr *storage.User
		if model.User != nil && model.User.ID != 0 {
			userCopy := storage.User{
				ID:        model.User.ID,
				Username:  model.User.Username,
				CreatedAt: model.User.CreatedAt,
				UpdatedAt: model.User.UpdatedAt,
			}
			userPtr = &userCopy
		}
		result[len(models)-1-i] = storage.Message{
			ID:        model.ID,
			Room:      model.Room,
			UserID:    model.UserID,
			Content:   model.Content,
			Kind:      model.Kind,
			FileSHA:   model.FileSHA,
			CreatedAt: model.CreatedAt,
			User:      userPtr,
		}
	}
	return result, nil
}

// GetMessageByID returns a single message by its identifier.
func (s *Store) GetMessageByID(ctx context.Context, id uint) (*storage.Message, error) {
	var model Message
	if err := s.db.WithContext(ctx).
		Preload("User").
		First(&model, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}

	var userPtr *storage.User
	if model.User != nil && model.User.ID != 0 {
		userCopy := storage.User{
			ID:        model.User.ID,
			Username:  model.User.Username,
			CreatedAt: model.User.CreatedAt,
			UpdatedAt: model.User.UpdatedAt,
		}
		userPtr = &userCopy
	}

	msg := &storage.Message{
		ID:        model.ID,
		Room:      model.Room,
		UserID:    model.UserID,
		Content:   model.Content,
		Kind:      model.Kind,
		FileSHA:   model.FileSHA,
		CreatedAt: model.CreatedAt,
		User:      userPtr,
	}
	return msg, nil
}
