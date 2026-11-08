package protocol

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
)

// The VPN link (docs: contracts/vpn-front): logos-vpn, core's client on an
// operator's machine, and core, for a tunnel task whose front is FrontVPN.
// A WebSocket on core's own address (GET VPNPath), the client's key its
// bearer (Authorization: Bearer lgv_…), which alone signs it in.
//
//   - Text frames are JSON, the link's own words (VPNControl): the client's
//     hello first, and again on each reconnect; core's welcome back to each,
//     then the routes each time they change, and end as it ends the client;
//     the client's bye as it disconnects.
//   - Binary frames are tunnel items (VPNFrame), a CBOR array of them, as a
//     minion's messages carry them: tunnel, tunnel_reply, tunnel_data,
//     tunnel_ack, tunnel_close and tunnel_datagram, their task the tunnel's.
//     The client opens every stream of the link, numbered from 1; core
//     answers, opening a stream of its own toward the minion for each. The
//     streams' rules are the minion's (offsets, windows, half closes, every
//     item safe to send twice), so a link that drops and comes back within
//     VPNLinkGrace loses nothing: each side sends again from the other's
//     last ack.
const (
	// VPNPath is the link's WebSocket, on core's own address.
	VPNPath = "/api/v1/vpn"
	// VPNLink is the link's version: core refuses a hello of another
	// (VPNCloseVersion), saying where its own client is.
	VPNLink = 1
	// VPNKeyPrefix starts a VPN key (lgv_…): one operator's, for one task.
	VPNKeyPrefix = "lgv_"
	// VPNKeyLapse is how long a key no client took lasts.
	VPNKeyLapse = 10 * time.Minute
	// VPNLinkGrace is how long a client whose link dropped is kept, its
	// streams open, for it to connect again; past it core ends it, and the
	// client gives up.
	VPNLinkGrace = 2 * time.Minute
	// MaxVPNClients bounds a VPN tunnel's clients connected at once.
	MaxVPNClients = 16
	// MaxVPNFrame bounds a binary frame; MaxVPNFrameItems the items in it.
	MaxVPNFrame      = 512 << 10
	MaxVPNFrameItems = 256
	// MaxVPNControl bounds a text frame.
	MaxVPNControl = 64 << 10
)

// The link's WebSocket closes past the WebSocket's own: why core did not
// take a client, in the close's reason.
const (
	// VPNCloseRefused: a key unknown, lapsed or another client's; a task
	// that is no running VPN tunnel; its operator no longer an operator of
	// the operation; the tunnel's MaxVPNClients connected already.
	VPNCloseRefused = 4000
	// VPNCloseVersion: a hello of another link version (VPNLink), or one
	// that does not read: the reason says where core's client is.
	VPNCloseVersion = 4001
)

// VPNControl is a text frame: one of its fields.
type VPNControl struct {
	Hello   *VPNHello   `json:"hello,omitempty"`
	Welcome *VPNWelcome `json:"welcome,omitempty"`
	// Routes are the tunnel's routes, changed (core → client).
	Routes []string `json:"routes,omitempty"`
	// End is why core ends the client (core → client): the task's Stop or
	// end, a Disconnect, the operator's role lost. The client takes its
	// routes away and exits.
	End string `json:"end,omitempty"`
	// Bye: the client disconnects (client → core), so core ends it at once.
	Bye bool `json:"bye,omitempty"`
}

// VPNHello is the client's first word, and its word again on each
// reconnect.
type VPNHello struct {
	// Link is the link's version the client speaks (VPNLink).
	Link int `json:"link"`
	// Version is the client's release, for people.
	Version string `json:"version"`
	// OS and Arch are the client's system (GOOS, GOARCH); Machine its
	// machine's name (its hostname).
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	Machine string `json:"machine"`
	// Instance is a random number the client takes as it starts (32 hex
	// digits): the key is its once it took it, and a reconnect repeats it.
	Instance string `json:"instance"`
}

// Validate checks the hello's fields: the link's version, short printable
// texts, and an instance of 32 hex digits.
func (h VPNHello) Validate() error {
	if h.Link != VPNLink {
		return fmt.Errorf("hello: link %d, this core speaks %d", h.Link, VPNLink)
	}
	for name, v := range map[string]string{"version": h.Version, "os": h.OS, "arch": h.Arch, "machine": h.Machine} {
		if err := vpnText(name, v, 64); err != nil {
			return err
		}
	}
	if b, err := hex.DecodeString(h.Instance); err != nil || len(b) != 16 {
		return errors.New("hello: instance is 32 hex digits")
	}
	return nil
}

// VPNWelcome is core's answer to each hello: what the client routes, and
// how much it may open.
type VPNWelcome struct {
	// Task is the tunnel task's id (a UUID): its items' task. Session and
	// Operation say where it runs, for people.
	Task      string `json:"task"`
	Session   int    `json:"session"`
	Operation string `json:"operation"`
	// User is the key's operator; Client core's name for this client, as
	// its streams say it (vpn: user@machine).
	User   string `json:"user"`
	Client string `json:"client"`
	// Routes are the tunnel's routes (ParamRoutes).
	Routes []string `json:"routes"`
	// MaxStreams is the task's max_streams, over every client's streams;
	// Opens what its command opens (OpenTCP, OpenUDP, OpenICMP).
	MaxStreams int      `json:"max_streams"`
	Opens      []string `json:"opens"`
}

// VPNFrame encodes tunnel items as a binary frame: a CBOR array, at most
// MaxVPNFrameItems items and MaxVPNFrame bytes.
func VPNFrame(items []cbor.RawMessage) ([]byte, error) {
	if len(items) > MaxVPNFrameItems {
		return nil, fmt.Errorf("vpn frame: %d items at most", MaxVPNFrameItems)
	}
	b, err := MarshalCBOR(items)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxVPNFrame {
		return nil, fmt.Errorf("vpn frame: %d bytes at most", MaxVPNFrame)
	}
	return b, nil
}

// ReadVPNFrame reads a binary frame's items, each as it came: a receiver
// reads each by its type (ItemType; an open with ReadTunnel).
func ReadVPNFrame(b []byte) ([]cbor.RawMessage, error) {
	if len(b) > MaxVPNFrame {
		return nil, fmt.Errorf("vpn frame: %d bytes at most", MaxVPNFrame)
	}
	var items []cbor.RawMessage
	if err := UnmarshalCBOR(b, &items); err != nil {
		return nil, fmt.Errorf("vpn frame: %w", err)
	}
	if len(items) > MaxVPNFrameItems {
		return nil, fmt.Errorf("vpn frame: %d items at most", MaxVPNFrameItems)
	}
	return items, nil
}

// vpnText checks a short text of a hello: printable UTF-8, max bytes at
// most, not empty.
func vpnText(name, v string, max int) error {
	switch {
	case strings.TrimSpace(v) == "":
		return fmt.Errorf("hello: %s", name)
	case len(v) > max:
		return fmt.Errorf("hello: %s is %d bytes at most", name, max)
	case !utf8.ValidString(v) || strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }):
		return fmt.Errorf("hello: %s is printable UTF-8", name)
	}
	return nil
}
