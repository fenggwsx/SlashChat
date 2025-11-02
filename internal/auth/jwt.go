package auth

import (
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/fenggwsx/SlashChat/internal/config"
)

// Claims represents JWT payload for authenticated users.
type Claims struct {
	UserID   uint   `json:"uid"`
	Username string `json:"uname"`
	jwt.RegisteredClaims
}

// NewToken generates a signed JWT for the provided subject.
func NewToken(cfg config.JWTConfig, userID uint, username string) (string, error) {
	now := time.Now()
	subject := strconv.FormatUint(uint64(userID), 10)
	claims := Claims{
		UserID:   userID,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(cfg.Expiration)),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    cfg.Issuer,
			Subject:   subject,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(cfg.Secret))
}

// ParseToken validates the provided token string and extracts claims.
func ParseToken(cfg config.JWTConfig, tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(cfg.Secret), nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}
	return nil, jwt.ErrTokenInvalidClaims
}
