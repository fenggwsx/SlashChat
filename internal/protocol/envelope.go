package protocol

import "time"

// MessageType enumerates high-level protocol intents.
type MessageType string

const (
	MessageTypeAuthRequest  MessageType = "auth_request"
	MessageTypeAuthResponse MessageType = "auth_response"
	MessageTypeEvent        MessageType = "event"
	MessageTypeCommand      MessageType = "command"
	MessageTypeAck          MessageType = "ack"
	MessageTypeFileChunk    MessageType = "file_chunk"
)

// Envelope wraps every payload sent over the wire.
type Envelope struct {
	ID        string                 `json:"id"`
	Type      MessageType            `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Token     string                 `json:"token,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	Payload   interface{}            `json:"payload,omitempty"`
}

// AckPayload represents acknowledgement semantics.
type AckPayload struct {
	ReferenceID string `json:"reference_id"`
	Status      string `json:"status"`
	Reason      string `json:"reason,omitempty"`
}

// FileChunkPayload transports chunked file contents encoded as base64.
type FileChunkPayload struct {
	Filename    string `json:"filename"`
	Room        string `json:"room"`
	Index       int    `json:"index"`
	TotalChunks int    `json:"total_chunks"`
	DataBase64  string `json:"data_base64"`
}

// AuthRequest carries login or registration data.
type AuthRequest struct {
	Action   string `json:"action"` // login or register
	Username string `json:"username"`
	Password string `json:"password"`
}

// AuthResponse returns token and status details to client.
type AuthResponse struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
	UserID    string `json:"user_id"`
}
