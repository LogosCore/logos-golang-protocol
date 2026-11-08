package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ICMP over a tunnel (TunnelKindICMP): an icmp stream's datagrams carry ICMP
// messages from their type on, with no IP header. Core sends echo requests
// alone; the minion sends back what answered each: an echo reply, or an
// error (unreachable, time exceeded) whose quoted packet is the echo it
// answers, its ICMP header alone. An echo's identifier is its sender's
// socket's, whatever the item says: a receiver matches answers by their
// host and sequence. The checksum is its sender's to fill (IPv4's; ICMPv6's
// needs addresses, and is 0), and a receiver ignores it.

// ICMP types an icmp stream carries: IPv4's, and ICMPv6's. A datagram's host
// says which (an IPv4 or an IPv6 address): type 3 is IPv4's unreachable and
// ICMPv6's time exceeded.
const (
	ICMPEchoReply       = 0
	ICMPDestUnreachable = 3
	ICMPEchoRequest     = 8
	ICMPTimeExceeded    = 11

	ICMPv6DestUnreachable = 1
	ICMPv6TimeExceeded    = 3
	ICMPv6EchoRequest     = 128
	ICMPv6EchoReply       = 129
)

// ICMP codes of the errors a tunnel's answers map to (IPv4's, ICMPv6's).
const (
	ICMPNetUnreachable    = 0
	ICMPHostUnreachable   = 1
	ICMPPortUnreachable   = 3
	ICMPAdminProhibited   = 13
	ICMPv6NoRoute         = 0
	ICMPv6AdminProhibited = 1
	ICMPv6AddrUnreachable = 3
	ICMPv6PortUnreachable = 4
)

// MaxICMPPayload bounds an echo's payload: a datagram's, past its header.
const MaxICMPPayload = MaxTunnelDatagram - 8

// ICMPMessage is an icmp stream's datagram data, read (ReadICMP): an echo,
// its identifier, sequence and payload; or an error and the echo it
// answers (Quoted: its type, identifier and sequence).
type ICMPMessage struct {
	Type, Code int
	ID, Seq    uint16
	Payload    []byte
	// Quoted is an error's: the echo request it answers.
	Quoted *ICMPMessage
}

// ICMPEchoTypes are the echo request and reply types of an address's family.
func ICMPEchoTypes(v6 bool) (request, reply int) {
	if v6 {
		return ICMPv6EchoRequest, ICMPv6EchoReply
	}
	return ICMPEchoRequest, ICMPEchoReply
}

// IsEcho reports whether m is an echo request or reply of its family.
func (m ICMPMessage) IsEcho(v6 bool) bool {
	req, rep := ICMPEchoTypes(v6)
	return m.Type == req || m.Type == rep
}

// IsError reports whether m is an error an echo can have: unreachable, or
// time exceeded, of its family.
func (m ICMPMessage) IsError(v6 bool) bool {
	if v6 {
		return m.Type == ICMPv6DestUnreachable || m.Type == ICMPv6TimeExceeded
	}
	return m.Type == ICMPDestUnreachable || m.Type == ICMPTimeExceeded
}

// ReadICMP reads an icmp stream's datagram data, v6 by its host's family: an
// echo request or reply (8 bytes of header, then its payload), or an error
// (8 bytes, then the echo request it answers, its first 8 bytes at least).
// Another type, or one too short, is an error: its receiver drops it.
func ReadICMP(data []byte, v6 bool) (ICMPMessage, error) {
	if len(data) < 8 {
		return ICMPMessage{}, errors.New("icmp: 8 bytes at least, its header")
	}
	m := ICMPMessage{Type: int(data[0]), Code: int(data[1])}
	switch {
	case m.IsEcho(v6):
		m.ID, m.Seq = binary.BigEndian.Uint16(data[4:]), binary.BigEndian.Uint16(data[6:])
		m.Payload = data[8:]
		if len(m.Payload) > MaxICMPPayload {
			return ICMPMessage{}, fmt.Errorf("icmp: a payload is %d bytes at most", MaxICMPPayload)
		}
		return m, nil
	case m.IsError(v6):
		if len(data) < 16 {
			return ICMPMessage{}, errors.New("icmp: an error quotes the echo it answers, 8 bytes at least")
		}
		q, err := ReadICMP(data[8:], v6)
		req, _ := ICMPEchoTypes(v6)
		if err != nil || q.Type != req {
			return ICMPMessage{}, errors.New("icmp: an error quotes the echo request it answers")
		}
		q.Payload = nil
		m.Quoted = &q
		return m, nil
	}
	return ICMPMessage{}, fmt.Errorf("icmp: type %d is no echo or error an echo has", m.Type)
}

// Bytes writes m as an icmp stream's datagram data, v6 by its host's family:
// an echo's header and payload, or an error's header and the echo it
// quotes (its header alone). IPv4's checksum is filled in; ICMPv6's is 0.
func (m ICMPMessage) Bytes(v6 bool) []byte {
	var b []byte
	if m.Quoted != nil {
		b = make([]byte, 8, 16)
		b = append(b, m.Quoted.Bytes(v6)[:8]...)
	} else {
		b = make([]byte, 8, 8+len(m.Payload))
		binary.BigEndian.PutUint16(b[4:], m.ID)
		binary.BigEndian.PutUint16(b[6:], m.Seq)
		b = append(b, m.Payload...)
	}
	b[0], b[1] = byte(m.Type), byte(m.Code)
	if !v6 {
		binary.BigEndian.PutUint16(b[2:], ICMPChecksum(b))
	}
	return b
}

// ICMPChecksum is the Internet checksum (RFC 1071) of b: IPv4's ICMP header
// checksum when b is the message with its checksum 0.
func ICMPChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
