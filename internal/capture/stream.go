package capture

import (
	"sort"
)

type Segment struct {
	Sequence uint32
	Data     []byte
}
type Stream struct {
	Base     uint32
	HaveBase bool
	SawSYN   bool
	Segments []Segment
	Stored   int
	Dropped  int
}
type Reassembled struct {
	Data          []byte
	Gaps          bool
	Conflicts     int
	Retransmitted int
	Midstream     bool
	Dropped       int
}

func (s *Stream) Add(packet Packet, budget *int, limit int) {
	if packet.Flags&2 != 0 {
		s.Base = packet.Sequence + 1
		s.HaveBase = true
		s.SawSYN = true
	}
	if len(packet.Payload) == 0 {
		return
	}
	sequence := packet.Sequence
	if packet.Flags&2 != 0 {
		sequence++
	}
	if !s.HaveBase {
		s.Base = sequence
		s.HaveBase = true
	}
	if len(s.Segments) >= 1024 || s.Stored+len(packet.Payload) > limit || *budget < len(packet.Payload) {
		s.Dropped += len(packet.Payload)
		return
	}
	data := append([]byte{}, packet.Payload...)
	s.Segments = append(s.Segments, Segment{sequence, data})
	s.Stored += len(data)
	*budget -= len(data)
}
func (s Stream) Build() Reassembled {
	result := Reassembled{Midstream: !s.SawSYN && len(s.Segments) > 0, Dropped: s.Dropped}
	if len(s.Segments) == 0 {
		return result
	}
	sorted := append([]Segment{}, s.Segments...)
	sort.SliceStable(sorted, func(i, j int) bool { return int32(sorted[i].Sequence-s.Base) < int32(sorted[j].Sequence-s.Base) })
	start := int64(int32(sorted[0].Sequence - s.Base))
	end := start
	for _, segment := range sorted {
		position := int64(int32(segment.Sequence - s.Base))
		if position > end {
			result.Gaps = true
			break
		}
		finish := position + int64(len(segment.Data))
		if finish > end {
			end = finish
		}
	}
	if end-start > int64(s.Stored) || end < start {
		result.Gaps = true
		return result
	}
	result.Data = make([]byte, int(end-start))
	filled := make([]bool, len(result.Data))
	for _, segment := range s.Segments {
		position := int64(int32(segment.Sequence-s.Base)) - start
		conflict := false
		for i, value := range segment.Data {
			offset := position + int64(i)
			if offset < 0 || offset >= int64(len(result.Data)) {
				continue
			}
			if filled[offset] {
				result.Retransmitted++
				if result.Data[offset] != value {
					conflict = true
				}
			} else {
				result.Data[offset] = value
				filled[offset] = true
			}
		}
		if conflict {
			result.Conflicts++
		}
	}
	if s.SawSYN && start != 0 {
		result.Gaps = true
	}
	return result
}
