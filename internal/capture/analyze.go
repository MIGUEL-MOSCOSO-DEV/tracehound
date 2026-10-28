package capture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"sort"
	"strings"
	"time"
)

type Options struct {
	MaxFlows      int
	MemoryMB      int
	StreamKB      int
	PortThreshold int
}

func (o *Options) Validate() error {
	if o.MaxFlows == 0 {
		o.MaxFlows = 2000
	}
	if o.MemoryMB == 0 {
		o.MemoryMB = 32
	}
	if o.StreamKB == 0 {
		o.StreamKB = 64
	}
	if o.PortThreshold == 0 {
		o.PortThreshold = 20
	}
	if o.MaxFlows < 1 || o.MaxFlows > 20000 || o.MemoryMB < 1 || o.MemoryMB > 512 || o.StreamKB < 1 || o.StreamKB > 1024 || o.PortThreshold < 5 || o.PortThreshold > 1000 {
		return errors.New("limits: flows 1..20000, memory MB 1..512, stream KB 1..1024, port threshold 5..1000")
	}
	return nil
}

type Flow struct {
	ID                  string          `json:"id"`
	Protocol            string          `json:"protocol"`
	A                   string          `json:"a"`
	B                   string          `json:"b"`
	First               string          `json:"first"`
	Last                string          `json:"last"`
	Packets             int             `json:"packets"`
	Bytes               int64           `json:"bytes"`
	SYN                 bool            `json:"syn"`
	SYNACK              bool            `json:"syn_ack"`
	ACK                 bool            `json:"ack"`
	RST                 bool            `json:"rst"`
	FIN                 bool            `json:"fin"`
	Gaps                bool            `json:"gaps"`
	Midstream           bool            `json:"midstream"`
	ConflictingOverlaps int             `json:"conflicting_overlaps"`
	RetransmittedBytes  int             `json:"retransmitted_bytes"`
	DroppedStreamBytes  int             `json:"dropped_stream_bytes"`
	HTTP                []*HTTPMetadata `json:"http"`
	TLS                 []*TLSMetadata  `json:"tls"`
	DNS                 []DNSQuestion   `json:"dns"`
	streams             [2]Stream
	synSequence         uint32
	synTime             time.Time
}
type Alert struct {
	Rule     string         `json:"rule"`
	Severity string         `json:"severity"`
	Subject  string         `json:"subject"`
	Summary  string         `json:"summary"`
	Evidence map[string]any `json:"evidence"`
}
type Coverage struct {
	Packets       int      `json:"packets"`
	Parsed        int      `json:"parsed"`
	Malformed     int      `json:"malformed"`
	Unsupported   int      `json:"unsupported"`
	Fragments     int      `json:"fragments"`
	Truncated     int      `json:"truncated"`
	DroppedFlows  int      `json:"dropped_flow_packets"`
	StoredBytes   int      `json:"stored_payload_bytes"`
	LimitedEvents int      `json:"omitted_detection_events"`
	Diagnostics   []string `json:"diagnostics"`
}
type Report struct {
	Schema        int      `json:"schema"`
	Tool          string   `json:"tool"`
	CreatedAt     string   `json:"created_at"`
	First         string   `json:"first"`
	Last          string   `json:"last"`
	Coverage      Coverage `json:"coverage"`
	Options       Options  `json:"options"`
	Flows         []Flow   `json:"flows"`
	Alerts        []Alert  `json:"alerts"`
	Complete      bool     `json:"complete"`
	CaptureSHA256 string   `json:"capture_sha256"`
}
type attempt struct {
	source, destination string
	port                uint16
	stamp               time.Time
}
type dnsEvent struct {
	client   string
	question DNSQuestion
	stamp    time.Time
}

func canonical(packet Packet) (string, int, netip.AddrPort, netip.AddrPort) {
	a, b := packet.Source, packet.Destination
	direction := 0
	if a.String() > b.String() {
		a, b = b, a
		direction = 1
	}
	return packet.Protocol + " " + a.String() + " <-> " + b.String(), direction, a, b
}
func Analyze(ctx context.Context, reader io.Reader, options Options, progress func(int)) (Report, error) {
	report := Report{Schema: 1, Tool: "TraceHound", CreatedAt: time.Now().UTC().Format(time.RFC3339), Flows: []Flow{}, Alerts: []Alert{}}
	if err := options.Validate(); err != nil {
		return report, err
	}
	report.Options = options
	capture, err := NewReader(reader)
	if err != nil {
		return report, err
	}
	budget := options.MemoryMB * 1024 * 1024
	initialBudget := budget
	flows := map[string]*Flow{}
	attempts := []attempt{}
	dnsEvents := []dnsEvent{}
	var first, last time.Time
	diagnostic := func(text string) {
		if len(report.Coverage.Diagnostics) < 30 {
			report.Coverage.Diagnostics = append(report.Coverage.Diagnostics, text)
		}
	}
	for {
		if err = ctx.Err(); err != nil {
			break
		}
		record, readErr := capture.Next()
		if readErr == io.EOF {
			report.Complete = true
			break
		}
		if readErr != nil {
			err = readErr
			break
		}
		report.Coverage.Packets++
		if progress != nil && report.Coverage.Packets%10000 == 0 {
			progress(report.Coverage.Packets)
		}
		if first.IsZero() || record.Time.Before(first) {
			first = record.Time
		}
		if last.IsZero() || record.Time.After(last) {
			last = record.Time
		}
		if record.Truncated {
			report.Coverage.Truncated++
		}
		packet, parseErr := Parse(record.Data, capture.Linktype)
		if parseErr != nil {
			if errors.Is(parseErr, ErrUnsupported) {
				report.Coverage.Unsupported++
			} else if errors.Is(parseErr, ErrFragment) {
				report.Coverage.Fragments++
			} else {
				report.Coverage.Malformed++
				diagnostic(fmt.Sprintf("packet %d: %s", report.Coverage.Packets, parseErr))
			}
			continue
		}
		report.Coverage.Parsed++
		key, direction, a, b := canonical(packet)
		flow := flows[key]
		if flow == nil {
			if len(flows) >= options.MaxFlows {
				report.Coverage.DroppedFlows++
				continue
			}
			flow = &Flow{ID: key, Protocol: packet.Protocol, A: a.String(), B: b.String(), First: record.Time.Format(time.RFC3339Nano), Last: record.Time.Format(time.RFC3339Nano), HTTP: []*HTTPMetadata{}, TLS: []*TLSMetadata{}, DNS: []DNSQuestion{}}
			flows[key] = flow
		}
		flow.Packets++
		flow.Bytes += int64(len(packet.Payload))
		stamp := record.Time.Format(time.RFC3339Nano)
		if stamp < flow.First {
			flow.First = stamp
		}
		if stamp > flow.Last {
			flow.Last = stamp
		}
		if packet.Protocol == "TCP" {
			flow.SYN = flow.SYN || packet.Flags&2 != 0 && packet.Flags&16 == 0
			flow.SYNACK = flow.SYNACK || packet.Flags&18 == 18
			flow.ACK = flow.ACK || packet.Flags&16 != 0
			flow.RST = flow.RST || packet.Flags&4 != 0
			flow.FIN = flow.FIN || packet.Flags&1 != 0
			if packet.Flags&2 != 0 && packet.Flags&16 == 0 && (flow.synTime.IsZero() || flow.synSequence != packet.Sequence || record.Time.Sub(flow.synTime) > 5*time.Second) {
				if len(attempts) < 50000 {
					attempts = append(attempts, attempt{packet.Source.Addr().String(), packet.Destination.Addr().String(), packet.Destination.Port(), record.Time})
				} else {
					report.Coverage.LimitedEvents++
				}
				flow.synSequence = packet.Sequence
				flow.synTime = record.Time
			}
			flow.streams[direction].Add(packet, &budget, options.StreamKB*1024)
		} else if packet.Source.Port() == 53 || packet.Destination.Port() == 53 {
			questions, dnsErr := DNS(packet.Payload)
			if dnsErr != nil {
				diagnostic("DNS: " + dnsErr.Error())
			} else {
				for _, question := range questions {
					if len(flow.DNS) < 20 {
						flow.DNS = append(flow.DNS, question)
					}
					client := packet.Source.Addr().String()
					if question.Response {
						client = packet.Destination.Addr().String()
					}
					if len(dnsEvents) < 50000 {
						dnsEvents = append(dnsEvents, dnsEvent{client, question, record.Time})
					} else {
						report.Coverage.LimitedEvents++
					}
				}
			}
		}
	}
	report.Coverage.StoredBytes = initialBudget - budget
	for _, flow := range flows {
		if flow.Protocol == "TCP" {
			for _, stream := range flow.streams {
				rebuilt := stream.Build()
				flow.Gaps = flow.Gaps || rebuilt.Gaps
				flow.Midstream = flow.Midstream || rebuilt.Midstream
				flow.ConflictingOverlaps += rebuilt.Conflicts
				flow.RetransmittedBytes += rebuilt.Retransmitted
				flow.DroppedStreamBytes += rebuilt.Dropped
				if metadata := HTTP(rebuilt.Data); metadata != nil {
					flow.HTTP = append(flow.HTTP, metadata)
				}
				if len(rebuilt.Data) > 0 && rebuilt.Data[0] == 22 {
					metadata, tlsErr := ClientHello(rebuilt.Data)
					if tlsErr != nil {
						diagnostic("TLS: " + tlsErr.Error())
					} else if metadata != nil {
						flow.TLS = append(flow.TLS, metadata)
					}
				}
				if a, parseErr := netip.ParseAddrPort(flow.A); parseErr == nil {
					b, _ := netip.ParseAddrPort(flow.B)
					if (a.Port() == 53 || b.Port() == 53) && len(rebuilt.Data) >= 2 {
						length := int(rebuilt.Data[0])<<8 | int(rebuilt.Data[1])
						if length <= len(rebuilt.Data)-2 {
							questions, dnsErr := DNS(rebuilt.Data[2 : 2+length])
							if dnsErr == nil && len(flow.DNS) < 20 {
								flow.DNS = append(flow.DNS, questions...)
							}
						}
					}
				}
			}
			if flow.SYN && !flow.SYNACK {
				report.Alerts = append(report.Alerts, Alert{"handshake-not-observed", "info", flow.ID, "SYN observado sin SYN-ACK en esta captura.", map[string]any{"syn": true, "syn_ack": false, "limitation": "capture may be one-sided or incomplete"}})
			}
			if flow.ConflictingOverlaps > 0 {
				report.Alerts = append(report.Alerts, Alert{"tcp-overlap-conflict", "warning", flow.ID, "Segmentos solapados contienen bytes diferentes.", map[string]any{"conflicts": flow.ConflictingOverlaps, "policy": "first observed bytes win"}})
			}
		}
		report.Flows = append(report.Flows, *flow)
	}
	report.Alerts = append(report.Alerts, detect(attempts, dnsEvents, options.PortThreshold)...)
	sort.Slice(report.Flows, func(i, j int) bool { return report.Flows[i].ID < report.Flows[j].ID })
	sort.Slice(report.Alerts, func(i, j int) bool {
		if report.Alerts[i].Rule == report.Alerts[j].Rule {
			return report.Alerts[i].Subject < report.Alerts[j].Subject
		}
		return report.Alerts[i].Rule < report.Alerts[j].Rule
	})
	if !first.IsZero() {
		report.First = first.Format(time.RFC3339Nano)
		report.Last = last.Format(time.RFC3339Nano)
	}
	return report, err
}
func entropy(text string) float64 {
	counts := map[rune]int{}
	for _, ch := range text {
		counts[ch]++
	}
	result := 0.0
	for _, count := range counts {
		p := float64(count) / float64(len(text))
		result -= p * math.Log2(p)
	}
	return result
}
func detect(attempts []attempt, events []dnsEvent, threshold int) []Alert {
	alerts := []Alert{}
	groups := map[string][]attempt{}
	beacons := map[string][]time.Time{}
	for _, item := range attempts {
		key := item.source + " -> " + item.destination
		groups[key] = append(groups[key], item)
		beaconKey := key + fmt.Sprintf(":%d", item.port)
		beacons[beaconKey] = append(beacons[beaconKey], item.stamp)
	}
	for subject, items := range groups {
		sort.Slice(items, func(i, j int) bool { return items[i].stamp.Before(items[j].stamp) })
		left := 0
		counts := map[uint16]int{}
		maximum := 0
		var windowStart, windowEnd time.Time
		for right, item := range items {
			counts[item.port]++
			for left < right && item.stamp.Sub(items[left].stamp) > 60*time.Second {
				old := items[left].port
				counts[old]--
				if counts[old] == 0 {
					delete(counts, old)
				}
				left++
			}
			if len(counts) > maximum {
				maximum = len(counts)
				windowStart = items[left].stamp
				windowEnd = item.stamp
			}
		}
		if maximum >= threshold {
			alerts = append(alerts, Alert{"port-sweep-pattern", "warning", subject, "Muchos puertos de destino reciben SYN en una ventana de 60 segundos.", map[string]any{"distinct_ports": maximum, "threshold": threshold, "start": windowStart.Format(time.RFC3339Nano), "end": windowEnd.Format(time.RFC3339Nano), "limitation": "a monitoring or inventory tool can produce this pattern"}})
		}
	}
	for subject, times := range beacons {
		if len(times) < 6 {
			continue
		}
		sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
		intervals := []float64{}
		for i := 1; i < len(times); i++ {
			value := times[i].Sub(times[i-1]).Seconds()
			if value > 1 {
				intervals = append(intervals, value)
			}
		}
		if len(intervals) < 5 {
			continue
		}
		sum := 0.0
		for _, value := range intervals {
			sum += value
		}
		mean := sum / float64(len(intervals))
		variance := 0.0
		for _, value := range intervals {
			variance += (value - mean) * (value - mean)
		}
		coefficient := math.Sqrt(variance/float64(len(intervals))) / mean
		if mean >= 2 && mean <= 3600 && coefficient <= .1 {
			alerts = append(alerts, Alert{"periodic-connection-pattern", "info", subject, "Conexiones con intervalos regulares; revisar su propósito.", map[string]any{"intervals": len(intervals), "mean_seconds": mean, "coefficient_of_variation": coefficient, "limitation": "scheduled legitimate traffic can be periodic"}})
		}
	}
	suspicious := map[string]map[string]bool{}
	responses := map[string][2]int{}
	for _, event := range events {
		q := event.question
		if q.Response {
			value := responses[event.client]
			value[0]++
			if q.RCode == 3 {
				value[1]++
			}
			responses[event.client] = value
			continue
		}
		labels := strings.Split(q.Name, ".")
		if len(labels) < 3 || len(labels[0]) < 40 || entropy(labels[0]) < 3.5 {
			continue
		}
		suffix := strings.Join(labels[len(labels)-2:], ".")
		key := event.client + " / " + suffix
		if suspicious[key] == nil {
			suspicious[key] = map[string]bool{}
		}
		suspicious[key][q.Name] = true
	}
	for subject, names := range suspicious {
		if len(names) >= 20 {
			alerts = append(alerts, Alert{"dns-long-label-pattern", "warning", subject, "Consultas con etiquetas largas y alta entropía; patrón compatible con codificación de datos.", map[string]any{"unique_names": len(names), "minimum_label_length": 40, "minimum_entropy": 3.5, "limitation": "two-label suffix grouping is heuristic, not public-suffix resolution; no tunneling conclusion"}})
		}
	}
	for client, value := range responses {
		if value[0] >= 20 && float64(value[1])/float64(value[0]) >= .8 {
			alerts = append(alerts, Alert{"dns-nxdomain-ratio", "info", client, "Alta proporción de respuestas NXDOMAIN.", map[string]any{"responses": value[0], "nxdomain": value[1], "limitation": "misconfiguration or discovery traffic can explain this"}})
		}
	}
	return alerts
}
