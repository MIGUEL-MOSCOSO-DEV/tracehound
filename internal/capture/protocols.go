package capture

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"strings"
)

type DNSQuestion struct {
	Name     string `json:"name"`
	Type     uint16 `json:"type"`
	Response bool   `json:"response"`
	RCode    uint8  `json:"rcode"`
}

func dnsName(data []byte, offset int) (string, int, error) {
	labels := []string{}
	next := -1
	visited := map[int]bool{}
	for count := 0; count < 128; count++ {
		if offset >= len(data) || visited[offset] {
			return "", 0, errors.New("invalid DNS compression pointer")
		}
		visited[offset] = true
		size := int(data[offset])
		offset++
		if size == 0 {
			if next < 0 {
				next = offset
			}
			name := strings.Join(labels, ".")
			if len(name) > 253 {
				return "", 0, errors.New("DNS name too long")
			}
			return name, next, nil
		}
		if size&0xc0 == 0xc0 {
			if offset >= len(data) {
				return "", 0, io.ErrUnexpectedEOF
			}
			pointer := ((size & 0x3f) << 8) | int(data[offset])
			if next < 0 {
				next = offset + 1
			}
			offset = pointer
			continue
		}
		if size > 63 || offset+size > len(data) {
			return "", 0, errors.New("invalid DNS label")
		}
		label := string(data[offset : offset+size])
		for _, ch := range label {
			if ch < 33 || ch > 126 {
				return "", 0, errors.New("non-printable DNS label")
			}
		}
		labels = append(labels, strings.ToLower(label))
		offset += size
	}
	return "", 0, errors.New("DNS pointer limit exceeded")
}
func DNS(data []byte) ([]DNSQuestion, error) {
	if len(data) < 12 {
		return nil, errors.New("short DNS header")
	}
	count := int(binary.BigEndian.Uint16(data[4:6]))
	if count > 20 {
		return nil, errors.New("DNS question limit exceeded")
	}
	result := []DNSQuestion{}
	offset := 12
	for i := 0; i < count; i++ {
		name, next, err := dnsName(data, offset)
		if err != nil {
			return nil, err
		}
		offset = next
		if offset+4 > len(data) {
			return nil, io.ErrUnexpectedEOF
		}
		result = append(result, DNSQuestion{Name: name, Type: binary.BigEndian.Uint16(data[offset : offset+2]), Response: data[2]&0x80 != 0, RCode: data[3] & 15})
		offset += 4
	}
	return result, nil
}

type HTTPMetadata struct {
	Method string `json:"method,omitempty"`
	Host   string `json:"host,omitempty"`
	Path   string `json:"path,omitempty"`
	Status int    `json:"status,omitempty"`
}

func HTTP(data []byte) *HTTPMetadata {
	reader := bufio.NewReader(bytes.NewReader(data))
	if bytes.HasPrefix(data, []byte("HTTP/")) {
		response, err := http.ReadResponse(reader, nil)
		if err == nil {
			return &HTTPMetadata{Status: response.StatusCode}
		}
		return nil
	}
	allowed := false
	for _, method := range []string{"GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS "} {
		if bytes.HasPrefix(data, []byte(method)) {
			allowed = true
		}
	}
	if !allowed {
		return nil
	}
	request, err := http.ReadRequest(reader)
	if err != nil {
		return nil
	}
	path := request.URL.EscapedPath()
	if len(path) > 300 {
		path = path[:300]
	}
	host := request.Host
	if len(host) > 253 {
		host = host[:253]
	}
	return &HTTPMetadata{Method: request.Method, Host: host, Path: path}
}

type TLSMetadata struct {
	ServerName        string   `json:"server_name,omitempty"`
	ClientHello       bool     `json:"client_hello"`
	LegacyVersion     uint16   `json:"legacy_version"`
	SupportedVersions []uint16 `json:"supported_versions,omitempty"`
	CipherCount       int      `json:"cipher_count"`
}

func ClientHello(data []byte) (*TLSMetadata, error) {
	handshake := []byte{}
	for len(data) >= 5 && len(handshake) < 128*1024 {
		if data[0] != 22 {
			return nil, nil
		}
		length := int(binary.BigEndian.Uint16(data[3:5]))
		if length > 18432 || len(data) < 5+length {
			return nil, errors.New("incomplete TLS handshake record")
		}
		handshake = append(handshake, data[5:5+length]...)
		data = data[5+length:]
		if len(handshake) >= 4 {
			size := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
			if size > 128*1024 {
				return nil, errors.New("ClientHello exceeds limit")
			}
			if len(handshake) >= size+4 {
				handshake = handshake[:size+4]
				break
			}
		}
	}
	if len(handshake) < 4 || handshake[0] != 1 {
		return nil, nil
	}
	length := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if len(handshake) < length+4 || length < 35 {
		return nil, errors.New("short ClientHello")
	}
	data = handshake[4:]
	result := &TLSMetadata{ClientHello: true, LegacyVersion: binary.BigEndian.Uint16(data[:2])}
	offset := 34
	if offset >= len(data) {
		return nil, io.ErrUnexpectedEOF
	}
	session := int(data[offset])
	offset += 1 + session
	if offset+2 > len(data) {
		return nil, io.ErrUnexpectedEOF
	}
	ciphers := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if ciphers%2 != 0 || offset+ciphers >= len(data) {
		return nil, errors.New("invalid cipher vector")
	}
	result.CipherCount = ciphers / 2
	offset += ciphers
	compression := int(data[offset])
	offset += 1 + compression
	if offset == len(data) {
		return result, nil
	}
	if offset+2 > len(data) {
		return nil, io.ErrUnexpectedEOF
	}
	extensions := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if offset+extensions > len(data) {
		return nil, io.ErrUnexpectedEOF
	}
	end := offset + extensions
	for offset+4 <= end {
		kind := binary.BigEndian.Uint16(data[offset : offset+2])
		size := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4
		if offset+size > end {
			return nil, errors.New("invalid TLS extension")
		}
		value := data[offset : offset+size]
		offset += size
		if kind == 0 {
			if len(value) < 2 || int(binary.BigEndian.Uint16(value[:2])) != len(value)-2 {
				return nil, errors.New("invalid SNI vector")
			}
			index := 2
			for index+3 <= len(value) {
				nameType := value[index]
				n := int(binary.BigEndian.Uint16(value[index+1 : index+3]))
				index += 3
				if index+n > len(value) {
					return nil, io.ErrUnexpectedEOF
				}
				if nameType == 0 && n <= 253 {
					result.ServerName = string(value[index : index+n])
				}
				index += n
			}
		}
		if kind == 43 {
			if len(value) < 1 || int(value[0]) != len(value)-1 || (len(value)-1)%2 != 0 {
				return nil, errors.New("invalid supported versions vector")
			}
			for index := 1; index+1 < len(value); index += 2 {
				result.SupportedVersions = append(result.SupportedVersions, binary.BigEndian.Uint16(value[index:index+2]))
			}
		}
	}
	if offset != end {
		return nil, errors.New("trailing TLS extension data")
	}
	return result, nil
}
