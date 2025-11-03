package client

import (
	"encoding/json"
	"fmt"

	"github.com/fenggwsx/SlashChat/internal/protocol"
)

func decodeAckPayload(payload interface{}) (protocol.AckPayload, error) {
	var ack protocol.AckPayload
	if payload == nil {
		return ack, fmt.Errorf("ack payload empty")
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return ack, err
	}
	if err := json.Unmarshal(data, &ack); err != nil {
		return ack, err
	}
	return ack, nil
}

func decodeAuthResponse(payload interface{}) (protocol.AuthResponse, error) {
	var resp protocol.AuthResponse
	if payload == nil {
		return resp, fmt.Errorf("auth response payload empty")
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return resp, err
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return resp, err
	}
	return resp, nil
}

func decodeChatHistory(payload interface{}) (protocol.ChatHistory, error) {
	var history protocol.ChatHistory
	if payload == nil {
		return history, fmt.Errorf("chat history payload empty")
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return history, err
	}
	if err := json.Unmarshal(data, &history); err != nil {
		return history, err
	}
	return history, nil
}

func decodeChatMessage(payload interface{}) (protocol.ChatMessage, error) {
	var msg protocol.ChatMessage
	if payload == nil {
		return msg, fmt.Errorf("chat message payload empty")
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return msg, err
	}
	if err := json.Unmarshal(data, &msg); err != nil {
		return msg, err
	}
	return msg, nil
}

func decodeFileDownloadPayload(payload interface{}) (protocol.FileDownloadPayload, error) {
	var dl protocol.FileDownloadPayload
	if payload == nil {
		return dl, fmt.Errorf("download payload empty")
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return dl, err
	}
	if err := json.Unmarshal(data, &dl); err != nil {
		return dl, err
	}
	return dl, nil
}

func metadataString(metadata map[string]interface{}, key string) string {
	if metadata == nil {
		return ""
	}
	if value, ok := metadata[key]; ok {
		if s, ok := value.(string); ok {
			return s
		}
	}
	return ""
}
