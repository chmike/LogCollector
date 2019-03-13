package main

import (
	"encoding/binary"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
)

// ErrUnknownEncoding is returned when the encoding is unknown.
var ErrUnknownEncoding = errors.New("unknown encoding")

// Msg is a monitoring log meessage.
type Msg struct {
	Stamp     time.Time `json:"stamp"`
	Level     string    `json:"level"`
	System    string    `json:"system"`
	Component string    `json:"component"`
	Message   string    `json:"message"`
}

// JSONEncode append json encoded message to buf.
func (m *Msg) JSONEncode(buf []byte) ([]byte, error) {
	jsonMsg, err := json.Marshal(m)
	if err != nil {
		return buf, errors.Wrap(err, "json encode")
	}
	buf = append(buf, 'J')
	return append(buf, jsonMsg...), nil
}

// JSONDecode decode the json encoded message in front of data.
func (m *Msg) JSONDecode(data []byte) error {
	if data[0] != 'J' {
		return ErrUnknownEncoding
	}
	return json.Unmarshal(data[1:], m)
}

// BinaryEncode append binary encoded message to buf.
func (m *Msg) BinaryEncode(buf []byte) ([]byte, error) {
	buf = append(buf, 'B')
	var b [8]byte
	sub, err := m.Stamp.MarshalBinary()
	if err != nil {
		return buf, errors.Wrap(err, "binary encode")
	}
	buf = append(buf, byte(len(sub)))
	buf = append(buf, sub...)
	binary.LittleEndian.PutUint32(b[:4], uint32(len(m.Level)))
	buf = append(buf, b[:4]...)
	buf = append(buf, []byte(m.Level)...)
	binary.LittleEndian.PutUint32(b[:4], uint32(len(m.System)))
	buf = append(buf, b[:4]...)
	buf = append(buf, []byte(m.System)...)
	binary.LittleEndian.PutUint32(b[:4], uint32(len(m.Component)))
	buf = append(buf, b[:4]...)
	buf = append(buf, []byte(m.Component)...)
	binary.LittleEndian.PutUint32(b[:4], uint32(len(m.Message)))
	buf = append(buf, b[:4]...)
	buf = append(buf, []byte(m.Message)...)
	return buf, nil
}

// BinaryDecode decode the binary encoded message in front of data.
func (m *Msg) BinaryDecode(data []byte) error {
	if data[0] != 'B' {
		return ErrUnknownEncoding
	}
	l := int(data[0])
	data = data[1:]
	if err := m.Stamp.UnmarshalBinary(data[:l]); err != nil {
		return errors.Wrap(err, "binary decode")
	}
	data = data[l:]
	l = int(binary.LittleEndian.Uint32(data[:4]))
	data = data[4:]
	m.Level = string(data[:l])
	data = data[l:]
	l = int(binary.LittleEndian.Uint32(data[:4]))
	data = data[4:]
	m.System = string(data[:l])
	data = data[l:]
	l = int(binary.LittleEndian.Uint32(data[:4]))
	data = data[4:]
	m.Component = string(data[:l])
	data = data[l:]
	l = int(binary.LittleEndian.Uint32(data[:4]))
	data = data[4:]
	if l != len(data) {
		err := errors.Errorf("expected len(data)= %d, got %d", len(data), l)
		return errors.Wrap(err, "binary decode")
	}
	m.Message = string(data)
	return nil
}
