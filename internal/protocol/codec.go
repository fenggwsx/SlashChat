package protocol

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

const frameHeaderBytes = 4

// Encoder writes envelopes with a length-prefixed JSON frame.
type Encoder struct {
	writer io.Writer
}

// Decoder reads envelopes with a length-prefixed JSON frame.
type Decoder struct {
	reader *bufio.Reader
}

// NewEncoder creates a new encoder for the given writer.
func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{writer: w}
}

// NewDecoder creates a new decoder for the given reader.
func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{reader: bufio.NewReader(r)}
}

// Encode writes the envelope to the underlying writer.
func (e *Encoder) Encode(ctx context.Context, env Envelope) error {
	data, err := json.Marshal(env)
	if err != nil {
		return err
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	length := uint32(len(data))
	header := make([]byte, frameHeaderBytes)
	binary.BigEndian.PutUint32(header, length)

	if _, err := e.writer.Write(header); err != nil {
		return err
	}

	_, err = e.writer.Write(data)
	return err
}

// Decode reads the next envelope from the stream.
func (d *Decoder) Decode(ctx context.Context) (Envelope, error) {
	var env Envelope

	header := make([]byte, frameHeaderBytes)
	if err := d.readFull(ctx, header); err != nil {
		return env, err
	}

	length := binary.BigEndian.Uint32(header)
	if length == 0 {
		return env, errors.New("frame length zero")
	}

	payload := make([]byte, length)
	if err := d.readFull(ctx, payload); err != nil {
		return env, err
	}

	if err := json.Unmarshal(payload, &env); err != nil {
		return env, err
	}

	return env, nil
}

func (d *Decoder) readFull(ctx context.Context, buf []byte) error {
	if len(buf) == 0 {
		return nil
	}

	read := 0
	for read < len(buf) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n, err := d.reader.Read(buf[read:])
		if err != nil {
			return err
		}
		read += n
	}
	return nil
}
