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
	MessageTypeFileUpload   MessageType = "file_upload"
	MessageTypeFileDownload MessageType = "file_download"
)

// MessageKind distinguishes persisted chat payload semantics.
type MessageKind string

const (
	MessageKindText MessageKind = "text"
	MessageKindFile MessageKind = "file"
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

// FileUploadRequest initiates a file upload negotiation.
type FileUploadRequest struct {
	Room     string `json:"room"`
	Filename string `json:"filename"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
}

// FileUploadPayload transports a complete file payload.
type FileUploadPayload struct {
	Room       string `json:"room"`
	Filename   string `json:"filename"`
	SHA256     string `json:"sha256"`
	DataBase64 string `json:"data_base64"`
}

// FileDownloadRequest asks the server to send the file for a stored message.
type FileDownloadRequest struct {
	MessageID uint `json:"message_id"`
}

// FileDownloadPayload delivers file contents for a specific message.
type FileDownloadPayload struct {
	MessageID  uint   `json:"message_id"`
	Filename   string `json:"filename"`
	SHA256     string `json:"sha256"`
	DataBase64 string `json:"data_base64"`
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
	UserID    uint   `json:"user_id"`
}

// JoinRequest instructs the server to subscribe the client to a room.
type JoinRequest struct {
	Room string `json:"room"`
}

// LeaveRequest instructs the server to remove a room subscription.
type LeaveRequest struct {
	Room string `json:"room"`
}

// ChatSendRequest represents a user-submitted chat message to a room.
type ChatSendRequest struct {
	Room    string `json:"room"`
	Content string `json:"content"`
}

// ChatMessage captures a persisted/broadcast chat entry.
type ChatMessage struct {
	ID        uint        `json:"id"`
	Room      string      `json:"room"`
	UserID    uint        `json:"user_id"`
	Username  string      `json:"username"`
	Content   string      `json:"content"`
	Kind      MessageKind `json:"kind"`
	Filename  string      `json:"filename,omitempty"`
	SHA256    string      `json:"sha256,omitempty"`
	CreatedAt int64       `json:"created_at"`
}

// ChatHistory bundles a batch of chat messages for a room.
type ChatHistory struct {
	Room     string        `json:"room"`
	Messages []ChatMessage `json:"messages"`
}
