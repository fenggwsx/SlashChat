package auth

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

const defaultCost = bcrypt.DefaultCost

// HashPassword encrypts the supplied plaintext with bcrypt.
func HashPassword(plaintext string) (string, error) {
	if plaintext == "" {
		return "", errors.New("empty password")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), defaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// ComparePassword verifies plaintext against a stored hash.
func ComparePassword(hash, plaintext string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext))
}
