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
	FileID    *uint     `gorm:"index"`
	CreatedAt time.Time `gorm:"index;not null"`
	User      *User     `gorm:"foreignKey:UserID"`
	File      *File     `gorm:"foreignKey:FileID"`
}

type File struct {
	ID        uint      `gorm:"primaryKey;autoIncrement"`
	Filename  string    `gorm:"not null"`
	SHA256    string    `gorm:"uniqueIndex;not null"`
	CreatedAt time.Time `gorm:"not null"`
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
	return s.db.WithContext(ctx).AutoMigrate(&User{}, &Message{}, &File{})
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
		FileID:    msg.FileID,
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
		Preload("File").
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
		var filePtr *storage.File
		if model.File != nil && model.File.ID != 0 {
			fileCopy := storage.File{
				ID:        model.File.ID,
				Filename:  model.File.Filename,
				SHA256:    model.File.SHA256,
				CreatedAt: model.File.CreatedAt,
			}
			filePtr = &fileCopy
		}
		result[len(models)-1-i] = storage.Message{
			ID:        model.ID,
			Room:      model.Room,
			UserID:    model.UserID,
			Content:   model.Content,
			Kind:      model.Kind,
			FileID:    model.FileID,
			CreatedAt: model.CreatedAt,
			User:      userPtr,
			File:      filePtr,
		}
	}
	return result, nil
}

// CreateFile persists a file metadata record.
func (s *Store) CreateFile(ctx context.Context, file *storage.File) error {
	if file == nil {
		return errors.New("nil file")
	}
	model := File{
		Filename:  file.Filename,
		SHA256:    file.SHA256,
		CreatedAt: file.CreatedAt,
	}
	if err := s.db.WithContext(ctx).Create(&model).Error; err != nil {
		return err
	}
	file.ID = model.ID
	return nil
}

// GetFileBySHA retrieves a file metadata record by SHA256 hash.
func (s *Store) GetFileBySHA(ctx context.Context, sha string) (*storage.File, error) {
	var model File
	if err := s.db.WithContext(ctx).Where("sha256 = ?", sha).First(&model).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	return &storage.File{
		ID:        model.ID,
		Filename:  model.Filename,
		SHA256:    model.SHA256,
		CreatedAt: model.CreatedAt,
	}, nil
}
