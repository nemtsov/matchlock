//go:build linux

package net

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// buildQuery crafts a minimal A/AAAA query for hostname.
func buildQuery(id uint16, qtype uint16, hostname string) []byte {
	q := make([]byte, 0, 32)
	var header [12]byte
	binary.BigEndian.PutUint16(header[0:2], id)
	header[2] = 0x01 // RD=1
	header[3] = 0x00
	binary.BigEndian.PutUint16(header[4:6], 1) // QDCOUNT
	q = append(q, header[:]...)

	for _, label := range splitLabels(hostname) {
		q = append(q, byte(len(label)))
		q = append(q, []byte(label)...)
	}
	q = append(q, 0x00) // null terminator

	var tail [4]byte
	binary.BigEndian.PutUint16(tail[0:2], qtype)
	binary.BigEndian.PutUint16(tail[2:4], 1) // class IN
	q = append(q, tail[:]...)
	return q
}

func splitLabels(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	return out
}

func TestBuildDNSResponseAReturnsSentinel(t *testing.T) {
	q := buildQuery(0xABCD, dnsTypeA, "api.anthropic.com")
	resp, ok := buildDNSResponse(q)
	if !ok {
		t.Fatalf("buildDNSResponse rejected a valid A query")
	}
	if binary.BigEndian.Uint16(resp[0:2]) != 0xABCD {
		t.Fatalf("response ID not echoed")
	}
	if resp[2]&0x80 == 0 {
		t.Fatalf("response QR bit not set")
	}
	if resp[2]&0x01 == 0 {
		t.Fatalf("response RD bit not copied from query")
	}
	if binary.BigEndian.Uint16(resp[6:8]) != 1 {
		t.Fatalf("expected exactly 1 answer for A query, got %d",
			binary.BigEndian.Uint16(resp[6:8]))
	}
	// Last 4 bytes of the response are the A record rdata.
	got := net.IPv4(resp[len(resp)-4], resp[len(resp)-3], resp[len(resp)-2], resp[len(resp)-1])
	if !got.Equal(SentinelIP) {
		t.Fatalf("answer rdata = %s, want %s", got, SentinelIP)
	}
	if name := parseQuestionName(resp); name != "api.anthropic.com" {
		t.Fatalf("question name round-trip = %q, want api.anthropic.com", name)
	}
}

func TestBuildDNSResponseAAAAEmpty(t *testing.T) {
	q := buildQuery(0x0001, dnsTypeAAAA, "example.com")
	resp, ok := buildDNSResponse(q)
	if !ok {
		t.Fatalf("buildDNSResponse rejected a valid AAAA query")
	}
	if ancount := binary.BigEndian.Uint16(resp[6:8]); ancount != 0 {
		t.Fatalf("AAAA response should have 0 answers, got %d", ancount)
	}
	// Response should be exactly header + echoed question (no answer).
	if len(resp) != len(q) {
		t.Fatalf("AAAA response length = %d, want %d (header + question only)", len(resp), len(q))
	}
}

func TestBuildDNSResponseRejectsMalformed(t *testing.T) {
	cases := [][]byte{
		nil,
		make([]byte, 5),                  // short
		append(make([]byte, 12), 0xC0, 0), // compression pointer in question — unexpected
	}
	for _, c := range cases {
		if _, ok := buildDNSResponse(c); ok {
			t.Fatalf("buildDNSResponse should have rejected %v", c)
		}
	}
}

func TestDNSForwarderEndToEnd(t *testing.T) {
	d, err := NewDNSForwarder("127.0.0.1")
	if err != nil {
		t.Fatalf("NewDNSForwarder: %v", err)
	}
	defer d.Close()

	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: d.Port()})
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(buildQuery(0x4242, dnsTypeA, "httpbin.org")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if binary.BigEndian.Uint16(buf[0:2]) != 0x4242 {
		t.Fatalf("id not echoed")
	}
	if binary.BigEndian.Uint16(buf[6:8]) != 1 {
		t.Fatalf("expected 1 answer, got %d", binary.BigEndian.Uint16(buf[6:8]))
	}
	got := net.IPv4(buf[n-4], buf[n-3], buf[n-2], buf[n-1])
	if !got.Equal(SentinelIP) {
		t.Fatalf("got %s, want %s", got, SentinelIP)
	}
}
