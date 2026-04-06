//go:build linux

package net

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/jingkaihe/matchlock/internal/errx"
)

// SentinelIP is the address returned by the DNS forwarder for every A query.
// It is drawn from RFC 5737 TEST-NET-1 (192.0.2.0/24 — reserved for
// documentation and never routable on the public Internet). The guest
// connects to this address for every hostname; nftables DNAT rules then
// redirect the TCP traffic into the transparent proxy, which extracts the
// real hostname from the HTTP Host header or TLS SNI and enforces policy.
var SentinelIP = net.IPv4(192, 0, 2, 1).To4()

// DNSForwarder is a tiny UDP server that answers every A query with
// SentinelIP and every AAAA query with an empty NOERROR response. It does
// not forward any traffic upstream: its sole purpose is to make the guest
// connect to SentinelIP, where the transparent proxy can then intercept
// the connection and log / enforce based on the real hostname seen in
// Host header or SNI.
type DNSForwarder struct {
	conn *net.UDPConn

	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
}

// NewDNSForwarder binds a UDP socket on bindAddr:0 (kernel-assigned port)
// and starts serving. The caller must call Close to shut it down.
func NewDNSForwarder(bindAddr string) (*DNSForwarder, error) {
	addr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:0", bindAddr))
	if err != nil {
		return nil, errx.With(ErrListen, " resolving DNS bind addr %s: %w", bindAddr, err)
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return nil, errx.With(ErrListen, " on DNS port %s: %w", addr, err)
	}
	d := &DNSForwarder{conn: conn}
	d.wg.Add(1)
	go d.serve()
	return d, nil
}

// Port returns the ephemeral port chosen by the kernel.
func (d *DNSForwarder) Port() int {
	return d.conn.LocalAddr().(*net.UDPAddr).Port
}

// Close stops the server and releases the socket.
func (d *DNSForwarder) Close() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	d.mu.Unlock()

	_ = d.conn.Close()
	d.wg.Wait()
	return nil
}

func (d *DNSForwarder) serve() {
	defer d.wg.Done()
	buf := make([]byte, 512) // RFC 1035 max UDP message size
	for {
		n, clientAddr, err := d.conn.ReadFromUDP(buf)
		if err != nil {
			d.mu.Lock()
			closed := d.closed
			d.mu.Unlock()
			if closed {
				return
			}
			continue
		}

		resp, ok := buildDNSResponse(buf[:n])
		if !ok {
			continue
		}
		_, _ = d.conn.WriteToUDP(resp, clientAddr)
	}
}

// DNS query/response types we care about.
const (
	dnsTypeA    = 1
	dnsTypeAAAA = 28
)

// buildDNSResponse parses a DNS query from req and constructs a response.
// For A queries it returns a single answer pointing at SentinelIP.
// For AAAA and other types it returns NOERROR with zero answers. Malformed
// queries result in ok=false (caller should drop the packet).
func buildDNSResponse(req []byte) ([]byte, bool) {
	if len(req) < 12 {
		return nil, false
	}
	qdcount := binary.BigEndian.Uint16(req[4:6])
	if qdcount != 1 {
		return nil, false
	}

	// Walk the question name to find where it ends (null label).
	off := 12
	for {
		if off >= len(req) {
			return nil, false
		}
		l := int(req[off])
		if l == 0 {
			off++
			break
		}
		if l&0xC0 != 0 {
			// Pointer in question name — not something a real stub
			// resolver emits; refuse.
			return nil, false
		}
		off += 1 + l
	}
	if off+4 > len(req) {
		return nil, false
	}
	qtype := binary.BigEndian.Uint16(req[off : off+2])
	// off+2..off+4 is qclass; we echo it in the response via the copied
	// question bytes, so no need to read it here.
	questionEnd := off + 4

	// Build the response: header (12) + question (echoed) + maybe answer.
	resp := make([]byte, 0, questionEnd+16)
	resp = append(resp, req[0:2]...) // ID

	// Flags: QR=1, OPCODE=0, AA=0, TC=0, RD=(copy), RA=1, Z=0, RCODE=0.
	rd := req[2] & 0x01
	resp = append(resp, 0x80|rd, 0x80)

	// QDCOUNT=1, ANCOUNT=(1 for A else 0), NSCOUNT=0, ARCOUNT=0.
	var ancount uint16
	if qtype == dnsTypeA {
		ancount = 1
	}
	var counts [8]byte
	binary.BigEndian.PutUint16(counts[0:2], 1)
	binary.BigEndian.PutUint16(counts[2:4], ancount)
	resp = append(resp, counts[:]...)

	// Echo the question section verbatim.
	resp = append(resp, req[12:questionEnd]...)

	if qtype == dnsTypeA {
		// Answer: NAME pointer to offset 12, TYPE=A, CLASS=IN, TTL=60,
		// RDLENGTH=4, RDATA=SentinelIP.
		answer := [...]byte{
			0xC0, 0x0C,
			0x00, byte(dnsTypeA),
			0x00, 0x01,
			0x00, 0x00, 0x00, 0x3C,
			0x00, 0x04,
			SentinelIP[0], SentinelIP[1], SentinelIP[2], SentinelIP[3],
		}
		resp = append(resp, answer[:]...)
	}

	return resp, true
}

// parseQuestionName extracts the queried hostname from a DNS message for
// diagnostic use. It is not used on the hot path (buildDNSResponse echoes
// the question bytes without decoding them) but is kept here so callers
// that want to log or inspect queries have a canonical implementation.
func parseQuestionName(req []byte) string {
	if len(req) < 12 {
		return ""
	}
	off := 12
	var labels []string
	for {
		if off >= len(req) {
			return ""
		}
		l := int(req[off])
		if l == 0 {
			break
		}
		if l&0xC0 != 0 {
			return ""
		}
		if off+1+l > len(req) {
			return ""
		}
		labels = append(labels, string(req[off+1:off+1+l]))
		off += 1 + l
	}
	return strings.Join(labels, ".")
}
