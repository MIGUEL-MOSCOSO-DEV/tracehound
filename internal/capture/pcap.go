package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

type Record struct {
	Time      time.Time
	Data      []byte
	Original  uint32
	Truncated bool
}
type Reader struct {
	reader   io.Reader
	order    binary.ByteOrder
	nano     bool
	Snaplen  uint32
	Linktype uint32
	Count    int
	LastTime time.Time
}

func NewReader(reader io.Reader) (*Reader, error) {
	header := make([]byte, 24)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, fmt.Errorf("PCAP global header: %w", err)
	}
	result := &Reader{reader: reader}
	switch string(header[:4]) {
	case "\xd4\xc3\xb2\xa1":
		result.order = binary.LittleEndian
	case "\xa1\xb2\xc3\xd4":
		result.order = binary.BigEndian
	case "\x4d\x3c\xb2\xa1":
		result.order = binary.LittleEndian
		result.nano = true
	case "\xa1\xb2\x3c\x4d":
		result.order = binary.BigEndian
		result.nano = true
	case "\x0a\x0d\x0d\x0a":
		return nil, errors.New("PCAPNG is not supported; export a classic PCAP first")
	default:
		return nil, errors.New("unsupported capture magic")
	}
	if result.order.Uint16(header[4:6]) != 2 || result.order.Uint16(header[6:8]) != 4 {
		return nil, errors.New("only PCAP version 2.4 is supported")
	}
	result.Snaplen = result.order.Uint32(header[16:20])
	result.Linktype = result.order.Uint32(header[20:24]) & 0xffff
	if result.Snaplen == 0 || result.Snaplen > 16*1024*1024 {
		return nil, errors.New("invalid or excessive snapshot length")
	}
	switch result.Linktype {
	case 1, 101, 113, 276:
	default:
		return nil, fmt.Errorf("unsupported link type %d; supported: Ethernet, raw IP, Linux cooked v1/v2", result.Linktype)
	}
	return result, nil
}
func (r *Reader) Next() (Record, error) {
	var record Record
	header := make([]byte, 16)
	count, err := io.ReadFull(r.reader, header)
	if err == io.EOF && count == 0 {
		return record, io.EOF
	}
	if err != nil {
		return record, fmt.Errorf("record header: %w", err)
	}
	seconds, fraction := r.order.Uint32(header[:4]), r.order.Uint32(header[4:8])
	included, original := r.order.Uint32(header[8:12]), r.order.Uint32(header[12:16])
	scale := uint32(1000000)
	multiplier := int64(1000)
	if r.nano {
		scale = 1000000000
		multiplier = 1
	}
	if fraction >= scale || included > r.Snaplen || included > 16*1024*1024 || included > original {
		return record, errors.New("invalid capture record length or timestamp")
	}
	record.Time = time.Unix(int64(seconds), int64(fraction)*multiplier).UTC()
	record.Data = make([]byte, included)
	record.Original = original
	record.Truncated = included < original
	if _, err = io.ReadFull(r.reader, record.Data); err != nil {
		return record, fmt.Errorf("packet data: %w", err)
	}
	r.Count++
	r.LastTime = record.Time
	return record, nil
}
