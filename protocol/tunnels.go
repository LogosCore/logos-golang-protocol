package protocol

import (
	"errors"
	"fmt"
	"math"
	"net"
	"time"
	"unicode/utf8"
)

// Tunnels (docs: contracts/minion-messages/tunnels): TCP connections a
// minion makes from its host, and UDP associations, whose bytes core and the
// minion carry in their messages. Core opens a stream for a task of a
// command whose action is a tunnel action (TunnelActions); the minion
// connects (or opens a UDP socket) and each side relays what its end sends.
// Core puts what the operator's tools speak in front of it (a SOCKS proxy,
// a port forward); the minion opens, relays and closes streams, nothing
// more. A reverse port forward (ActionReversePortForward) goes the other
// way: the minion listens on its host, says where with a tunnel_listen,
// and opens a stream for each connection that comes there; core connects
// each to the task's destination, which the minion never learns. A UDP
// one listens for datagrams: a stream for each address they come from (a
// udp tunnel naming it), its datagrams going as tunnel_datagram items, core
// sending them on from a socket of the stream's own, and the stream ending
// once it idled TunnelUDPIdle.
//
// Every item names its task and the stream in it: a number the side that
// opens it gives from 1, never reused within the task. Core opens a SOCKS
// proxy's and a port forward's streams (tunnel, core → minion;
// tunnel_reply, minion → core), the minion a reverse port forward's
// (tunnel, minion → core, from the address that connected; tunnel_reply,
// core → minion, with no Bound and no Msg: core says nothing of its side).
// A task's streams are all one side's. Each item is safe to send again:
//
//   - tunnel for a stream its receiver has: its tunnel_reply again.
//   - tunnel_data: each direction is a byte stream from 0, and the eof takes
//     one place after the last byte, as TCP's FIN does. A receiver keeps an
//     item only when its Off is where it has the stream (its next), so one
//     sent again is not kept twice; it answers with a tunnel_ack.
//   - tunnel_ack: Next (every byte before it received) and Room (what the
//     receiver takes past Next). A sender keeps every byte until an ack
//     covers it and sends nothing past Next+Room. An ack whose Next is
//     below the last taken is ignored; one with the same Next updates Room.
//   - tunnel_close: the stream is over; one for a stream gone is nothing.
//     An item about a stream its receiver does not have (other than a
//     close) is answered with tunnel_close TunnelCloseUnknown; a tunnel for
//     a task its receiver does not run as a tunnel whose streams the sender
//     opens, with TunnelCloseTaskEnded.
//   - tunnel_listen: the task's listener, again; it changes nothing.
//   - tunnel_datagram: a receiver takes one only when its Seq is above the
//     last it took on the stream; there are no acks: as UDP is, one that
//     does not fit, or finds the other side's queue full, is dropped.
//
// A stream is over when both directions reached their eof and each side has
// the other's: the side that sees it sends tunnel_close TunnelCloseDone and
// drops the stream. An end that aborts sends TunnelCloseReset.

// Limits of tunnels.
const (
	// MaxTunnelData is the most a tunnel_data carries.
	MaxTunnelData = 64 << 10
	// DefaultTunnelRoom is a stream's window each way, unless a side says
	// another as it opens.
	DefaultTunnelRoom = 256 << 10
	// MaxTunnelRoom is the largest window a side may give.
	MaxTunnelRoom = 16 << 20
	// MaxTunnelHost bounds a destination's (or a datagram's source's) host:
	// a DNS name or an address.
	MaxTunnelHost = 255
	// MaxTunnelBound bounds a reply's bound address ("ip:port").
	MaxTunnelBound = 128
	// MaxTunnelMsg bounds the messages for a person, in bytes.
	MaxTunnelMsg = 256
	// MaxTunnelDatagram is the largest datagram payload.
	MaxTunnelDatagram = 65535
	// TunnelUDPIdle ends a UDP reverse port forward's stream with no
	// datagram either way for that long: the minion closes it (done), and
	// core, a minute later still, as a backstop.
	TunnelUDPIdle = 2 * time.Minute
)

// TunnelItem opens a stream. Core → minion: a TCP connection to Host:Port
// from the minion's host, or (UDP) a UDP association, a socket the minion
// opens for the datagrams core sends through it. Minion → core, in a
// reverse port forward: a connection that came to the minion's listener
// from Host:Port, which core connects to the task's destination.
type TunnelItem struct {
	T int `cbor:"0,keyasint"`
	// Task is the tunnel task (16 bytes); Stream its number in the task,
	// its sender's.
	Task   []byte `cbor:"1,keyasint"`
	Stream uint64 `cbor:"2,keyasint"`
	// Host is a name, which the minion resolves on its host (so internal
	// names work), or an IPv4 or IPv6 address; Port 1 to 65535. Neither for
	// a UDP association core opens. From the minion: the address that
	// connected, or that a UDP stream's datagrams come from.
	Host string `cbor:"3,keyasint,omitempty"`
	Port uint64 `cbor:"4,keyasint,omitempty"`
	// Room is what the sender takes of the stream past an ack (its
	// window): DefaultTunnelRoom when nil.
	Room *uint64 `cbor:"5,keyasint,omitempty"`
	// UDP: a UDP association, not a TCP connection.
	UDP bool `cbor:"6,keyasint,omitempty"`
}

// Validate checks the task, the stream, the address (for UDP none, or a
// reverse port forward's source) and the window.
func (t TunnelItem) Validate() error {
	if err := tunnelStream("tunnel", t.Task, t.Stream); err != nil {
		return err
	}
	if t.UDP {
		if (t.Host != "" || t.Port != 0) && tunnelPeer("tunnel", t.Host, t.Port) != nil {
			return errors.New("tunnel: a udp stream names no address, or a whole one: host and port")
		}
	} else if err := tunnelPeer("tunnel", t.Host, t.Port); err != nil {
		return err
	}
	return tunnelRoom("tunnel", t.Room)
}

// TunnelReplyItem answers a tunnel: open, or why not. Minion → core for
// the streams core opens; core → minion for a reverse port forward's, with
// no Bound and no Msg (core says nothing of its side).
type TunnelReplyItem struct {
	T      int    `cbor:"0,keyasint"`
	Task   []byte `cbor:"1,keyasint"`
	Stream uint64 `cbor:"2,keyasint"`
	// Result is TunnelOpen, or why not (TunnelRefused, ...). One this
	// version does not know reads as TunnelFailed.
	Result int `cbor:"3,keyasint"`
	// Bound is the local address of the minion's socket, "ip:port" (as
	// net.JoinHostPort writes it), when open: the address the stream leaves
	// the host from.
	Bound string `cbor:"4,keyasint,omitempty"`
	// Room is what the replier takes of the stream past an ack:
	// DefaultTunnelRoom when nil.
	Room *uint64 `cbor:"5,keyasint,omitempty"`
	// Msg says why, for a person, when not open.
	Msg string `cbor:"6,keyasint,omitempty"`
}

// Tunnel results: a tunnel_reply's Result.
const (
	// TunnelOpen: connected (or the UDP socket open).
	TunnelOpen = 0
	// TunnelRefused: nothing listens there.
	TunnelRefused = 1
	// TunnelHostUnreachable: the host is unreachable, or its name does not
	// resolve.
	TunnelHostUnreachable = 2
	// TunnelNetUnreachable: the network is unreachable.
	TunnelNetUnreachable = 3
	// TunnelTimedOut: the connect timed out (the command's timeout).
	TunnelTimedOut = 4
	// TunnelNotAllowed: the minion takes no more streams (its max_streams).
	TunnelNotAllowed = 5
	// TunnelFailed: another failure; Msg says.
	TunnelFailed = 6
)

var tunnelResultNames = map[int]string{
	TunnelOpen: "open", TunnelRefused: "refused", TunnelHostUnreachable: "host_unreachable",
	TunnelNetUnreachable: "net_unreachable", TunnelTimedOut: "timed_out", TunnelNotAllowed: "not_allowed",
	TunnelFailed: "failed",
}

// TunnelResultName is a result's name, for people: "result 9" for one this
// version does not know.
func TunnelResultName(r int) string {
	if n, ok := tunnelResultNames[r]; ok {
		return n
	}
	return fmt.Sprintf("result %d", r)
}

// Validate checks the task, the stream, the result and the texts.
func (r TunnelReplyItem) Validate() error {
	if err := tunnelStream("tunnel_reply", r.Task, r.Stream); err != nil {
		return err
	}
	switch {
	case r.Result < 0:
		return errors.New("tunnel_reply: result is 0 (open) or why not")
	case len(r.Bound) > MaxTunnelBound:
		return fmt.Errorf("tunnel_reply: bound is %d bytes at most", MaxTunnelBound)
	}
	if err := tunnelMsg("tunnel_reply", r.Msg); err != nil {
		return err
	}
	return tunnelRoom("tunnel_reply", r.Room)
}

// TunnelDataItem is bytes of a stream, one direction (both ways): Data from
// Off in its sender's bytes, and EOF when its sender sends no more after
// them (its end closed for writing). The eof takes one place after the last
// byte: End is what an ack of the item says.
type TunnelDataItem struct {
	T      int    `cbor:"0,keyasint"`
	Task   []byte `cbor:"1,keyasint"`
	Stream uint64 `cbor:"2,keyasint"`
	Off    uint64 `cbor:"3,keyasint"`
	// Data is at most MaxTunnelData, within the connection's max_message.
	Data []byte `cbor:"4,keyasint,omitempty"`
	EOF  bool   `cbor:"5,keyasint,omitempty"`
}

// End is the offset after the item, its eof counted: the next a receiver
// that has it acks.
func (d TunnelDataItem) End() uint64 {
	end := d.Off + uint64(len(d.Data))
	if d.EOF {
		end++
	}
	return end
}

// Validate checks the task, the stream, the size, and that the item says
// something (data, or the eof).
func (d TunnelDataItem) Validate() error {
	if err := tunnelStream("tunnel_data", d.Task, d.Stream); err != nil {
		return err
	}
	switch {
	case len(d.Data) > MaxTunnelData:
		return fmt.Errorf("tunnel_data: data of %d bytes is over %d", len(d.Data), MaxTunnelData)
	case len(d.Data) == 0 && !d.EOF:
		return errors.New("tunnel_data: data or eof")
	case d.Off > math.MaxUint64-uint64(len(d.Data))-1:
		return errors.New("tunnel_data: off past the end of offsets")
	}
	return nil
}

// TunnelAckItem says how far its sender has a stream's other direction
// (both ways): every byte before Next, and Room more it takes past Next.
type TunnelAckItem struct {
	T      int    `cbor:"0,keyasint"`
	Task   []byte `cbor:"1,keyasint"`
	Stream uint64 `cbor:"2,keyasint"`
	Next   uint64 `cbor:"3,keyasint"`
	// Room is what the sender takes past Next; unchanged when nil. 0 stops
	// the other side until an ack gives room again.
	Room *uint64 `cbor:"4,keyasint,omitempty"`
}

// Validate checks the task, the stream and the window.
func (a TunnelAckItem) Validate() error {
	if err := tunnelStream("tunnel_ack", a.Task, a.Stream); err != nil {
		return err
	}
	return tunnelRoom("tunnel_ack", a.Room)
}

// TunnelCloseItem says a stream is over (both ways), and why.
type TunnelCloseItem struct {
	T      int    `cbor:"0,keyasint"`
	Task   []byte `cbor:"1,keyasint"`
	Stream uint64 `cbor:"2,keyasint"`
	// Reason is TunnelCloseDone, TunnelCloseReset, ... One this version does
	// not know reads as a reset.
	Reason int `cbor:"3,keyasint"`
	// Msg is for a person.
	Msg string `cbor:"4,keyasint,omitempty"`
}

// Tunnel close reasons: a tunnel_close's Reason.
const (
	// TunnelCloseDone: both directions reached their eof, and each side
	// has the other's.
	TunnelCloseDone = 1
	// TunnelCloseReset: one end aborted (the operator's tool, or the host).
	TunnelCloseReset = 2
	// TunnelCloseUnknown: the sender does not have the stream (one of a
	// connection that went): the receiver drops it.
	TunnelCloseUnknown = 3
	// TunnelCloseTaskEnded: the task ended, or is ending, or the minion
	// runs no such tunnel task.
	TunnelCloseTaskEnded = 4
)

var tunnelCloseNames = map[int]string{
	TunnelCloseDone: "done", TunnelCloseReset: "reset", TunnelCloseUnknown: "unknown",
	TunnelCloseTaskEnded: "task_ended",
}

// TunnelCloseName is a close reason's name, for people: "reason 9" for one
// this version does not know.
func TunnelCloseName(r int) string {
	if n, ok := tunnelCloseNames[r]; ok {
		return n
	}
	return fmt.Sprintf("reason %d", r)
}

// Validate checks the task, the stream, the reason and the text.
func (c TunnelCloseItem) Validate() error {
	if err := tunnelStream("tunnel_close", c.Task, c.Stream); err != nil {
		return err
	}
	if c.Reason < 1 {
		return errors.New("tunnel_close: reason is 1 (done) or more")
	}
	return tunnelMsg("tunnel_close", c.Msg)
}

// TunnelDatagramItem is one datagram of a UDP association (both ways): core
// → minion to Host:Port, the destination; minion → core from Host:Port, the
// source. In a UDP reverse port forward the stream's source is both: the
// minion's from it, core's to it (the minion sends them from its
// listener).
type TunnelDatagramItem struct {
	T      int    `cbor:"0,keyasint"`
	Task   []byte `cbor:"1,keyasint"`
	Stream uint64 `cbor:"2,keyasint"`
	// Seq is its number in its direction, from 0: a receiver takes one only
	// when it is above the last it took, so one sent again is dropped.
	Seq  uint64 `cbor:"3,keyasint"`
	Host string `cbor:"4,keyasint"`
	Port uint64 `cbor:"5,keyasint"`
	// Data is the payload, at most MaxTunnelDatagram, within the
	// connection's max_message; it may be empty.
	Data []byte `cbor:"6,keyasint"`
}

// Validate checks the task, the stream, the address and the size.
func (d TunnelDatagramItem) Validate() error {
	if err := tunnelStream("tunnel_datagram", d.Task, d.Stream); err != nil {
		return err
	}
	if err := tunnelPeer("tunnel_datagram", d.Host, d.Port); err != nil {
		return err
	}
	if len(d.Data) > MaxTunnelDatagram {
		return fmt.Errorf("tunnel_datagram: data of %d bytes is over %d", len(d.Data), MaxTunnelDatagram)
	}
	return nil
}

// TunnelListenItem says a reverse port forward's listener is up (minion →
// core): Bound, the address the minion listens at, "ip:port" (as
// net.JoinHostPort writes it). Sent as the task starts; again, it changes
// nothing. A minion whose listener does not open ends the task, saying why,
// and sends none.
type TunnelListenItem struct {
	T     int    `cbor:"0,keyasint"`
	Task  []byte `cbor:"1,keyasint"`
	Bound string `cbor:"2,keyasint"`
}

// Validate checks the task and the address.
func (l TunnelListenItem) Validate() error {
	if len(l.Task) != 16 {
		return errors.New("tunnel_listen: task is 16 bytes")
	}
	if len(l.Bound) > MaxTunnelBound {
		return fmt.Errorf("tunnel_listen: bound is %d bytes at most", MaxTunnelBound)
	}
	if host, port, err := net.SplitHostPort(l.Bound); err != nil || host == "" || port == "" {
		return errors.New("tunnel_listen: bound is the address it listens at, ip:port")
	}
	return nil
}

// TunnelListen checks where a reverse port forward listens: bind, an
// address of the minion's host (0.0.0.0 or :: for all of them) or a name it
// resolves there, and listen, a port from 1 to 65535, or 0 for any free
// one.
func TunnelListen(bind string, listen int64) error {
	switch {
	case listen < 0 || listen > 65535:
		return errors.New("listen: a port from 0 (any free one) to 65535")
	case bind == "":
		return errors.New("bind: an address of the minion's host (0.0.0.0 for all of them)")
	}
	return tunnelPeer("bind", bind, 1)
}

// TunnelRoom is a window as an opening item says it: DefaultTunnelRoom when
// it says none.
func TunnelRoom(room *uint64) uint64 {
	if room == nil {
		return DefaultTunnelRoom
	}
	return *room
}

func tunnelStream(item string, task []byte, stream uint64) error {
	switch {
	case len(task) != 16:
		return fmt.Errorf("%s: task is 16 bytes", item)
	case stream == 0:
		return fmt.Errorf("%s: stream is a number from 1", item)
	}
	return nil
}

// tunnelPeer checks a host and a port: a name or an address, printable, and
// a port 1 to 65535.
func tunnelPeer(item, host string, port uint64) error {
	switch {
	case host == "":
		return fmt.Errorf("%s: a host", item)
	case len(host) > MaxTunnelHost:
		return fmt.Errorf("%s: host is %d bytes at most", item, MaxTunnelHost)
	case !utf8.ValidString(host):
		return fmt.Errorf("%s: host is UTF-8", item)
	case port == 0 || port > 65535:
		return fmt.Errorf("%s: port is 1 to 65535", item)
	}
	for _, r := range host {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s: host has a control character", item)
		}
	}
	return nil
}

func tunnelRoom(item string, room *uint64) error {
	if room != nil && *room > MaxTunnelRoom {
		return fmt.Errorf("%s: room is %d bytes at most", item, MaxTunnelRoom)
	}
	return nil
}

func tunnelMsg(item, msg string) error {
	switch {
	case len(msg) > MaxTunnelMsg:
		return fmt.Errorf("%s: msg is %d bytes at most", item, MaxTunnelMsg)
	case !utf8.ValidString(msg):
		return fmt.Errorf("%s: msg is UTF-8", item)
	}
	return nil
}
