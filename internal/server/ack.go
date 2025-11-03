package server

import (
	"context"
	"log"
	"time"

	"github.com/google/uuid"

	"github.com/fenggwsx/SlashChat/internal/protocol"
)

const (
	ackStatusOK             = "ok"
	ackStatusError          = "error"
	ackStatusUploadRequired = "upload_required"
)

func (a *App) sendAck(ctx context.Context, session *clientSession, referenceID, status, reason string) {
	ack := protocol.Envelope{
		ID:        uuid.NewString(),
		Type:      protocol.MessageTypeAck,
		Timestamp: time.Now(),
		Payload: protocol.AckPayload{
			ReferenceID: referenceID,
			Status:      status,
			Reason:      reason,
		},
	}
	if err := session.send(ctx, ack); err != nil {
		log.Printf("send ack: %v", err)
	}
}
