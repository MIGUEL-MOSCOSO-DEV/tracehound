package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

type Packet struct {
	Source, Destination netip.AddrPort
	Protocol            string
	Payload             []byte
	Sequence            uint32
	Flags               byte
	Fragmented          bool
}

var ErrUnsupported = errors.New("unsupported protocol")
var ErrFragment = errors.New("fragmented IP datagram; reassembly not performed")

func Parse(data []byte, link uint32) (Packet, error) {
	var packet Packet
	switch link {
	case 1:
		if len(data) < 14 {
			return packet, errors.New("short Ethernet frame")
		}
		kind := binary.BigEndian.Uint16(data[12:14])
		data = data[14:]
		for tags := 0; kind == 0x8100 || kind == 0x88a8; tags++ {
			if tags >= 2 || len(data) < 4 {
				return packet, errors.New("invalid VLAN headers")
			}
			kind = binary.BigEndian.Uint16(data[2:4])
			data = data[4:]
		}
		if kind != 0x0800 && kind != 0x86dd {
			return packet, ErrUnsupported
		}
	case 113:
		if len(data) < 16 {
			return packet, errors.New("short Linux cooked header")
		}
		kind := binary.BigEndian.Uint16(data[14:16])
		data = data[16:]
		if kind != 0x0800 && kind != 0x86dd {
			return packet, ErrUnsupported
		}
	case 276:
		if len(data) < 20 {
			return packet, errors.New("short Linux cooked v2 header")
		}
		kind := binary.BigEndian.Uint16(data[:2])
		data = data[20:]
		if kind != 0x0800 && kind != 0x86dd {
			return packet, ErrUnsupported
		}
	case 101:
	default:
		return packet, ErrUnsupported
	}
	if len(data) < 1 {
		return packet, errors.New("missing IP header")
	}
	var source, destination netip.Addr
	var protocol byte
	switch data[0] >> 4 {
	case 4:
		if len(data) < 20 {
			return packet, errors.New("short IPv4 header")
		}
		length := int(data[0]&15) * 4
		total := int(binary.BigEndian.Uint16(data[2:4]))
		if length < 20 || total < length || len(data) < total {
			return packet, errors.New("truncated IPv4 packet")
		}
		if binary.BigEndian.Uint16(data[6:8])&0x3fff != 0 {
			return packet, ErrFragment
		}
		source = netip.AddrFrom4([4]byte(data[12:16]))
		destination = netip.AddrFrom4([4]byte(data[16:20]))
		protocol = data[9]
		data = data[length:total]
	case 6:
		if len(data) < 40 {
			return packet, errors.New("short IPv6 header")
		}
		total := 40 + int(binary.BigEndian.Uint16(data[4:6]))
		if len(data) < total {
			return packet, errors.New("truncated IPv6 packet")
		}
		source = netip.AddrFrom16([16]byte(data[8:24]))
		destination = netip.AddrFrom16([16]byte(data[24:40]))
		protocol = data[6]
		data = data[40:total]
		for count := 0; protocol == 0 || protocol == 43 || protocol == 60 || protocol == 51 || protocol == 44; count++ {
			if count >= 8 || len(data) < 8 {
				return packet, errors.New("invalid IPv6 extension chain")
			}
			if protocol == 44 {
				return packet, ErrFragment
			}
			length := (int(data[1]) + 1) * 8
			if protocol == 51 {
				length = (int(data[1]) + 2) * 4
			}
			if length > len(data) {
				return packet, errors.New("short IPv6 extension")
			}
			protocol = data[0]
			data = data[length:]
		}
	default:
		return packet, ErrUnsupported
	}
	switch protocol {
	case 6:
		if len(data) < 20 {
			return packet, errors.New("short TCP header")
		}
		length := int(data[12]>>4) * 4
		if length < 20 || length > len(data) {
			return packet, errors.New("invalid TCP header length")
		}
		packet.Protocol = "TCP"
		packet.Source = netip.AddrPortFrom(source, binary.BigEndian.Uint16(data[:2]))
		packet.Destination = netip.AddrPortFrom(destination, binary.BigEndian.Uint16(data[2:4]))
		packet.Sequence = binary.BigEndian.Uint32(data[4:8])
		packet.Flags = data[13]
		packet.Payload = data[length:]
	case 17:
		if len(data) < 8 {
			return packet, errors.New("short UDP header")
		}
		length := int(binary.BigEndian.Uint16(data[4:6]))
		if length < 8 || length > len(data) {
			return packet, errors.New("invalid UDP length")
		}
		packet.Protocol = "UDP"
		packet.Source = netip.AddrPortFrom(source, binary.BigEndian.Uint16(data[:2]))
		packet.Destination = netip.AddrPortFrom(destination, binary.BigEndian.Uint16(data[2:4]))
		packet.Payload = data[8:length]
	default:
		return packet, fmt.Errorf("%w: IP %d", ErrUnsupported, protocol)
	}
	return packet, nil
}
