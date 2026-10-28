package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func pcap(records [][]byte, stamps []uint32, order binary.ByteOrder, nano bool) []byte {
	var output bytes.Buffer
	magic := uint32(0xa1b2c3d4)
	if nano {
		magic = 0xa1b23c4d
	}
	binary.Write(&output, order, magic)
	binary.Write(&output, order, uint16(2))
	binary.Write(&output, order, uint16(4))
	binary.Write(&output, order, uint32(0))
	binary.Write(&output, order, uint32(0))
	binary.Write(&output, order, uint32(65535))
	binary.Write(&output, order, uint32(1))
	for i, record := range records {
		stamp := uint32(i)
		if stamps != nil {
			stamp = stamps[i]
		}
		binary.Write(&output, order, stamp)
		binary.Write(&output, order, uint32(0))
		binary.Write(&output, order, uint32(len(record)))
		binary.Write(&output, order, uint32(len(record)))
		output.Write(record)
	}
	return output.Bytes()
}
func ipv4TCP(source, destination uint16, sequence uint32, flags byte, payload []byte) []byte {
	result := make([]byte, 14+20+20+len(payload))
	binary.BigEndian.PutUint16(result[12:14], 0x0800)
	ip := result[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], []byte{192, 0, 2, 1})
	copy(ip[16:20], []byte{192, 0, 2, 2})
	tcp := ip[20:]
	binary.BigEndian.PutUint16(tcp[:2], source)
	binary.BigEndian.PutUint16(tcp[2:4], destination)
	binary.BigEndian.PutUint32(tcp[4:8], sequence)
	tcp[12] = 0x50
	tcp[13] = flags
	copy(tcp[20:], payload)
	return result
}
func dnsQuery(name string) []byte {
	result := make([]byte, 12)
	binary.BigEndian.PutUint16(result[4:6], 1)
	for _, label := range strings.Split(name, ".") {
		result = append(result, byte(len(label)))
		result = append(result, []byte(label)...)
	}
	return append(result, 0, 0, 1, 0, 1)
}
func analyze(t *testing.T, records [][]byte, stamps []uint32, options Options) Report {
	t.Helper()
	report, err := Analyze(context.Background(), bytes.NewReader(pcap(records, stamps, binary.LittleEndian, false)), options, nil)
	if err != nil {
		t.Fatal(err)
	}
	return report
}
func TestPCAPEndianAndTimestampResolution(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, nano := range []bool{false, true} {
			reader, err := NewReader(bytes.NewReader(pcap([][]byte{{1, 2, 3}}, []uint32{10}, order, nano)))
			if err != nil {
				t.Fatal(err)
			}
			record, err := reader.Next()
			if err != nil || record.Time.Unix() != 10 || len(record.Data) != 3 {
				t.Fatal(record, err)
			}
			if _, err = reader.Next(); err != io.EOF {
				t.Fatal(err)
			}
		}
	}
}
func TestTruncatedCaptureIsRejected(t *testing.T) {
	data := pcap([][]byte{{1, 2, 3}}, nil, binary.LittleEndian, false)
	reader, err := NewReader(bytes.NewReader(data[:len(data)-1]))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = reader.Next(); err == nil {
		t.Fatal("truncated record accepted")
	}
}
func TestPCAPNGIsExplicitlyUnsupported(t *testing.T) {
	data := make([]byte, 24)
	copy(data, []byte{0x0a, 0x0d, 0x0d, 0x0a})
	if _, err := NewReader(bytes.NewReader(data)); err == nil || !strings.Contains(err.Error(), "PCAPNG") {
		t.Fatal(err)
	}
}
func TestExcessiveRecordLengthRejectedBeforeAllocation(t *testing.T) {
	data := pcap([][]byte{{1}}, nil, binary.LittleEndian, false)
	binary.LittleEndian.PutUint32(data[32:36], 0xffffffff)
	reader, _ := NewReader(bytes.NewReader(data))
	if _, err := reader.Next(); err == nil {
		t.Fatal("oversized allocation accepted")
	}
}
func TestIPv4TCPParsing(t *testing.T) {
	packet, err := Parse(ipv4TCP(50000, 443, 100, 2, []byte("hello")), 1)
	if err != nil || packet.Source.Port() != 50000 || packet.Destination.Port() != 443 || packet.Sequence != 100 || string(packet.Payload) != "hello" {
		t.Fatal(packet, err)
	}
}
func TestVLANAndLinuxCookedHeaders(t *testing.T) {
	ethernet := ipv4TCP(1000, 80, 1, 16, nil)
	vlan := append([]byte{}, ethernet[:12]...)
	vlan = append(vlan, 0x81, 0, 0, 1, 8, 0)
	vlan = append(vlan, ethernet[14:]...)
	if _, err := Parse(vlan, 1); err != nil {
		t.Fatal(err)
	}
	cooked := make([]byte, 16)
	binary.BigEndian.PutUint16(cooked[14:16], 0x0800)
	cooked = append(cooked, ethernet[14:]...)
	if _, err := Parse(cooked, 113); err != nil {
		t.Fatal(err)
	}
}
func TestIPv6TCPParsing(t *testing.T) {
	data := make([]byte, 40+20)
	data[0] = 0x60
	binary.BigEndian.PutUint16(data[4:6], 20)
	data[6] = 6
	source := netip.MustParseAddr("2001:db8::1").As16()
	destination := netip.MustParseAddr("2001:db8::2").As16()
	copy(data[8:24], source[:])
	copy(data[24:40], destination[:])
	binary.BigEndian.PutUint16(data[40:42], 5000)
	binary.BigEndian.PutUint16(data[42:44], 443)
	data[52] = 0x50
	packet, err := Parse(data, 101)
	if err != nil || !packet.Source.Addr().Is6() {
		t.Fatal(packet, err)
	}
}
func TestFragmentsAreCountedAsCoverageGap(t *testing.T) {
	data := ipv4TCP(1000, 80, 0, 0, nil)
	data[20] = 0x20
	if _, err := Parse(data, 1); !errors.Is(err, ErrFragment) {
		t.Fatal(err)
	}
	report := analyze(t, [][]byte{data}, nil, Options{})
	if report.Coverage.Fragments != 1 || report.Coverage.Parsed != 0 {
		t.Fatal(report.Coverage)
	}
}
func TestOutOfOrderTCPAndRetransmission(t *testing.T) {
	stream := Stream{}
	budget := 1000
	stream.Add(Packet{Sequence: 100, Flags: 2}, &budget, 1000)
	stream.Add(Packet{Sequence: 106, Payload: []byte("world")}, &budget, 1000)
	stream.Add(Packet{Sequence: 101, Payload: []byte("hello")}, &budget, 1000)
	stream.Add(Packet{Sequence: 101, Payload: []byte("hello")}, &budget, 1000)
	result := stream.Build()
	if string(result.Data) != "helloworld" || result.Gaps || result.Retransmitted != 5 {
		t.Fatal(result)
	}
}
func TestTCPSequenceWraparound(t *testing.T) {
	stream := Stream{}
	budget := 100
	stream.Add(Packet{Sequence: 0xfffffffc, Flags: 2}, &budget, 100)
	stream.Add(Packet{Sequence: 0, Payload: []byte("def")}, &budget, 100)
	stream.Add(Packet{Sequence: 0xfffffffd, Payload: []byte("abc")}, &budget, 100)
	if result := stream.Build(); string(result.Data) != "abcdef" || result.Gaps {
		t.Fatal(result)
	}
}
func TestConflictingTCPOverlapUsesFirstObserved(t *testing.T) {
	stream := Stream{}
	budget := 100
	stream.Add(Packet{Sequence: 100, Payload: []byte("hello")}, &budget, 100)
	stream.Add(Packet{Sequence: 100, Payload: []byte("jello")}, &budget, 100)
	result := stream.Build()
	if result.Conflicts != 1 || string(result.Data) != "hello" {
		t.Fatal(result)
	}
}
func TestTCPGapsDoNotFabricateMissingBytes(t *testing.T) {
	stream := Stream{}
	budget := 100
	stream.Add(Packet{Sequence: 100, Payload: []byte("first")}, &budget, 100)
	stream.Add(Packet{Sequence: 200, Payload: []byte("last")}, &budget, 100)
	result := stream.Build()
	if !result.Gaps || string(result.Data) != "first" {
		t.Fatal(result)
	}
}
func TestPayloadBudgetIsEnforced(t *testing.T) {
	stream := Stream{}
	budget := 5
	stream.Add(Packet{Sequence: 1, Payload: []byte("12345")}, &budget, 10)
	stream.Add(Packet{Sequence: 6, Payload: []byte("67890")}, &budget, 10)
	result := stream.Build()
	if stream.Stored != 5 || budget != 0 || result.Dropped != 5 {
		t.Fatal(result, stream)
	}
}
func TestDNSQuestionAndPointerLoop(t *testing.T) {
	questions, err := DNS(dnsQuery("api.company.test"))
	if err != nil || questions[0].Name != "api.company.test" {
		t.Fatal(questions, err)
	}
	data := make([]byte, 14)
	binary.BigEndian.PutUint16(data[4:6], 1)
	data[12], data[13] = 0xc0, 12
	if _, err := DNS(data); err == nil {
		t.Fatal("DNS pointer loop accepted")
	}
}
func TestHTTPMetadataNeverIncludesCredentialsOrQuery(t *testing.T) {
	data := []byte("GET /objects/123?token=private HTTP/1.1\r\nHost: api.company.test\r\nAuthorization: Bearer PRIVATE-CREDENTIAL\r\nCookie: session=PRIVATE\r\n\r\n")
	metadata := HTTP(data)
	if metadata == nil || metadata.Path != "/objects/123" || metadata.Host != "api.company.test" {
		t.Fatal(metadata)
	}
}
func TestHTTPResponseStatus(t *testing.T) {
	metadata := HTTP([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"))
	if metadata == nil || metadata.Status != 403 {
		t.Fatal(metadata)
	}
}
func hello(name string) []byte {
	body := make([]byte, 34)
	body[0], body[1] = 3, 3
	body = append(body, 0, 0, 2, 0x13, 1, 1, 0)
	sni := []byte{0, 0, 0, 0, byte(len(name))}
	sni = append(sni, []byte(name)...)
	binary.BigEndian.PutUint16(sni[:2], uint16(len(sni)-2))
	extension := []byte{0, 0, 0, byte(len(sni))}
	extension = append(extension, sni...)
	extension = append(extension, 0, 43, 0, 3, 2, 3, 4)
	body = append(body, byte(len(extension)>>8), byte(len(extension)))
	body = append(body, extension...)
	handshake := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)
	record := []byte{22, 3, 1, byte(len(handshake) >> 8), byte(len(handshake))}
	return append(record, handshake...)
}
func TestClientHelloExtractsSNIAndSupportedVersions(t *testing.T) {
	metadata, err := ClientHello(hello("api.company.test"))
	if err != nil || metadata == nil || metadata.ServerName != "api.company.test" || len(metadata.SupportedVersions) != 1 || metadata.SupportedVersions[0] != 0x0304 {
		t.Fatal(metadata, err)
	}
}
func TestTruncatedTLSProducesNoInventedMetadata(t *testing.T) {
	data := hello("api.company.test")
	if metadata, err := ClientHello(data[:len(data)-1]); err == nil || metadata != nil {
		t.Fatal(metadata, err)
	}
}
func TestPortSweepPatternHasCountedEvidence(t *testing.T) {
	records := [][]byte{}
	for port := uint16(1); port <= 20; port++ {
		records = append(records, ipv4TCP(50000, port, 100, 2, nil))
	}
	report := analyze(t, records, nil, Options{})
	found := false
	for _, alert := range report.Alerts {
		if alert.Rule == "port-sweep-pattern" {
			found = true
			if alert.Evidence["distinct_ports"] != 20 {
				t.Fatal(alert)
			}
		}
	}
	if !found {
		t.Fatal("sweep missed")
	}
}
func TestPeriodicConnectionsAndLegitimateLimitation(t *testing.T) {
	records := [][]byte{}
	stamps := []uint32{}
	for i := 0; i < 6; i++ {
		records = append(records, ipv4TCP(50000, 443, uint32(i*100+1), 2, nil))
		stamps = append(stamps, uint32(i*10))
	}
	report := analyze(t, records, stamps, Options{})
	found := false
	for _, alert := range report.Alerts {
		if alert.Rule == "periodic-connection-pattern" {
			found = true
			if alert.Evidence["mean_seconds"] != float64(10) {
				t.Fatal(alert)
			}
		}
	}
	if !found {
		t.Fatal("periodicity missed")
	}
}
func TestFlowLimitIsReported(t *testing.T) {
	report := analyze(t, [][]byte{ipv4TCP(1000, 80, 1, 2, nil), ipv4TCP(1001, 80, 1, 2, nil)}, nil, Options{MaxFlows: 1})
	if len(report.Flows) != 1 || report.Coverage.DroppedFlows != 1 {
		t.Fatal(report.Coverage)
	}
}
func TestCancelledAnalysisIsMarkedPartial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report, err := Analyze(ctx, bytes.NewReader(pcap(nil, nil, binary.LittleEndian, false)), Options{}, nil)
	if err == nil || report.Complete {
		t.Fatal(report, err)
	}
}
func TestCaptureOrderDoesNotChangeOverallBounds(t *testing.T) {
	report := analyze(t, [][]byte{ipv4TCP(1000, 80, 1, 2, nil), ipv4TCP(1000, 80, 2, 16, nil)}, []uint32{20, 10}, Options{})
	start, _ := time.Parse(time.RFC3339Nano, report.First)
	end, _ := time.Parse(time.RFC3339Nano, report.Last)
	if start.Unix() != 10 || end.Unix() != 20 {
		t.Fatal(report.First, report.Last)
	}
}
func FuzzPacket(f *testing.F) {
	f.Add(ipv4TCP(1000, 80, 1, 2, []byte("seed")), uint32(1))
	f.Add([]byte{}, uint32(101))
	f.Fuzz(func(t *testing.T, data []byte, link uint32) { _, _ = Parse(data, link) })
}
func FuzzDNS(f *testing.F) {
	f.Add(dnsQuery("api.company.test"))
	f.Add([]byte{0xc0, 0})
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = DNS(data) })
}
func FuzzTLS(f *testing.F) {
	f.Add(hello("api.company.test"))
	f.Add([]byte{22, 3, 3, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = ClientHello(data) })
}

func TestOverlapPolicyRespectsArrivalOrderAcrossDifferentOffsets(t *testing.T) {
	stream := Stream{}
	budget := 100
	stream.Add(Packet{Sequence: 103, Payload: []byte("XYZ")}, &budget, 100)
	stream.Add(Packet{Sequence: 100, Payload: []byte("abcdef")}, &budget, 100)
	result := stream.Build()
	if string(result.Data) != "abcXYZ" || result.Conflicts != 1 {
		t.Fatal(result)
	}
}

func TestDNSHeuristicsRequireSufficientEvidence(t *testing.T) {
	events := []dnsEvent{}
	for i := 0; i < 20; i++ {
		name := string(rune('a'+i)) + "0123456789abcdefghijklmnopqrstuvwxyz0123456789.example.test"
		events = append(events, dnsEvent{client: "192.0.2.1", question: DNSQuestion{Name: name}})
		events = append(events, dnsEvent{client: "192.0.2.1", question: DNSQuestion{Name: name, Response: true, RCode: 3}})
	}
	alerts := detect(nil, events, 20)
	found := map[string]bool{}
	for _, alert := range alerts {
		found[alert.Rule] = true
	}
	if !found["dns-long-label-pattern"] || !found["dns-nxdomain-ratio"] {
		t.Fatal(alerts)
	}
	if len(detect(nil, events[:2], 20)) != 0 {
		t.Fatal("insufficient evidence reported")
	}
}
