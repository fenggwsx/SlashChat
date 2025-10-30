package config

import (
	"os"
	"strconv"
	"time"
)

// ServerConfig holds settings for the TCP server runtime.
type ServerConfig struct {
	ListenAddr    string
	Database      DatabaseConfig
	JWT           JWTConfig
	ReadTimeout   time.Duration
	WriteTimeout  time.Duration
	MaxFrameBytes int
}

// ClientConfig holds settings for the terminal client.
type ClientConfig struct {
	ServerAddr    string
	CommandPrefix rune
}

// DatabaseConfig captures storage configuration.
type DatabaseConfig struct {
	Path string
}

// JWTConfig defines token issuance parameters.
type JWTConfig struct {
	Secret     string
	Issuer     string
	Expiration time.Duration
}

// LoadServerConfig builds the server configuration from environment variables with sensible defaults.
func LoadServerConfig() ServerConfig {
	return ServerConfig{
		ListenAddr:    envOrDefault("GOSLASH_LISTEN_ADDR", ":9000"),
		Database:      DatabaseConfig{Path: envOrDefault("GOSLASH_DB_PATH", "goslash.db")},
		JWT:           loadJWTConfig(),
		ReadTimeout:   envDuration("GOSLASH_READ_TIMEOUT", 15*time.Second),
		WriteTimeout:  envDuration("GOSLASH_WRITE_TIMEOUT", 15*time.Second),
		MaxFrameBytes: envInt("GOSLASH_MAX_FRAME_BYTES", 1<<20),
	}
}

// LoadClientConfig builds the client configuration from environment variables.
func LoadClientConfig() ClientConfig {
	prefix := envOrDefault("GOSLASH_COMMAND_PREFIX", "/")
	runes := []rune(prefix)
	commandPrefix := '/'
	if len(runes) > 0 {
		commandPrefix = runes[0]
	}
	return ClientConfig{
		ServerAddr:    envOrDefault("GOSLASH_SERVER_ADDR", "localhost:9000"),
		CommandPrefix: commandPrefix,
	}
}

func loadJWTConfig() JWTConfig {
	expiration := envDuration("GOSLASH_JWT_EXPIRATION", 24*time.Hour)
	return JWTConfig{
		Secret:     envOrDefault("GOSLASH_JWT_SECRET", "replace-me"),
		Issuer:     envOrDefault("GOSLASH_JWT_ISSUER", "goslash"),
		Expiration: expiration,
	}
}

func envOrDefault(key, value string) string {
	if env, ok := os.LookupEnv(key); ok {
		return env
	}
	return value
}

func envDuration(key string, def time.Duration) time.Duration {
	if env, ok := os.LookupEnv(key); ok {
		if parsed, err := time.ParseDuration(env); err == nil {
			return parsed
		}
	}
	return def
}

func envInt(key string, def int) int {
	if env, ok := os.LookupEnv(key); ok {
		if parsed, err := strconv.Atoi(env); err == nil {
			return parsed
		}
	}
	return def
}
