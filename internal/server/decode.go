package server

import (
	"encoding/json"

	"github.com/fenggwsx/SlashChat/internal/protocol"
)

func decodeJoinRequest(payload interface{}) (protocol.JoinRequest, error) {
	var req protocol.JoinRequest
	if payload == nil {
		return req, errInvalidPayload
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return req, err
	}
	if err := json.Unmarshal(data, &req); err != nil {
		return req, err
	}
	return req, nil
}

func decodeLeaveRequest(payload interface{}) (protocol.LeaveRequest, error) {
	var req protocol.LeaveRequest
	if payload == nil {
		return req, errInvalidPayload
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return req, err
	}
	if err := json.Unmarshal(data, &req); err != nil {
		return req, err
	}
	return req, nil
}

func decodeChatSendRequest(payload interface{}) (protocol.ChatSendRequest, error) {
	var req protocol.ChatSendRequest
	if payload == nil {
		return req, errInvalidPayload
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return req, err
	}
	if err := json.Unmarshal(data, &req); err != nil {
		return req, err
	}
	return req, nil
}

func decodeFileUploadRequest(payload interface{}) (protocol.FileUploadRequest, error) {
	var req protocol.FileUploadRequest
	if payload == nil {
		return req, errInvalidPayload
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return req, err
	}
	if err := json.Unmarshal(data, &req); err != nil {
		return req, err
	}
	return req, nil
}

func decodeFileUploadPayload(payload interface{}) (protocol.FileUploadPayload, error) {
	var req protocol.FileUploadPayload
	if payload == nil {
		return req, errInvalidPayload
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return req, err
	}
	if err := json.Unmarshal(data, &req); err != nil {
		return req, err
	}
	return req, nil
}

func decodeFileDownloadRequest(payload interface{}) (protocol.FileDownloadRequest, error) {
	var req protocol.FileDownloadRequest
	if payload == nil {
		return req, errInvalidPayload
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return req, err
	}
	if err := json.Unmarshal(data, &req); err != nil {
		return req, err
	}
	return req, nil
}
