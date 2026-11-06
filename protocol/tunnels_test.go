package protocol

import (
	"bytes"
	"math"
	"strings"
	"testing"
)

// Each tunnel item names its task and a stream from 1; an opening names a
// destination (none for UDP), a reply a result, data says something, a
// close a reason; sizes and windows keep to their limits.
func TestTunnelItems(t *testing.T) {
	task := bytes.Repeat([]byte{7}, 16)
	room, big := uint64(64<<10), uint64(MaxTunnelRoom+1)
	zero := uint64(0)
	type v interface{ Validate() error }
	ok := map[string]v{
		"tunnel to a name":          TunnelItem{T: ItemTunnel, Task: task, Stream: 1, Host: "dc01.corp.local", Port: 445},
		"tunnel to an IPv6 address": TunnelItem{T: ItemTunnel, Task: task, Stream: 2, Host: "fe80::1", Port: 22, Room: &room},
		"udp association":           TunnelItem{T: ItemTunnel, Task: task, Stream: 3, UDP: true},
		"reply open":                TunnelReplyItem{T: ItemTunnelReply, Task: task, Stream: 1, Result: TunnelOpen, Bound: "10.0.0.7:51234", Room: &room},
		"reply refused":             TunnelReplyItem{T: ItemTunnelReply, Task: task, Stream: 1, Result: TunnelRefused, Msg: "connection refused"},
		"reply a later result":      TunnelReplyItem{T: ItemTunnelReply, Task: task, Stream: 1, Result: 42},
		"data":                      TunnelDataItem{T: ItemTunnelData, Task: task, Stream: 1, Off: 10, Data: []byte("GET /")},
		"eof alone":                 TunnelDataItem{T: ItemTunnelData, Task: task, Stream: 1, Off: 15, EOF: true},
		"data and eof":              TunnelDataItem{T: ItemTunnelData, Task: task, Stream: 1, Data: make([]byte, MaxTunnelData), EOF: true},
		"ack":                       TunnelAckItem{T: ItemTunnelAck, Task: task, Stream: 1, Next: 16},
		"ack that stops":            TunnelAckItem{T: ItemTunnelAck, Task: task, Stream: 1, Next: 16, Room: &zero},
		"close":                     TunnelCloseItem{T: ItemTunnelClose, Task: task, Stream: 1, Reason: TunnelCloseReset, Msg: "reset by peer"},
		"close a later reason":      TunnelCloseItem{T: ItemTunnelClose, Task: task, Stream: 1, Reason: 9},
		"datagram":                  TunnelDatagramItem{T: ItemTunnelDatagram, Task: task, Stream: 3, Seq: 0, Host: "10.0.0.53", Port: 53, Data: []byte{1}},
		"empty datagram":            TunnelDatagramItem{T: ItemTunnelDatagram, Task: task, Stream: 3, Seq: 1, Host: "10.0.0.53", Port: 53},
	}
	for name, it := range ok {
		if err := it.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := map[string]v{
		"tunnel, short task":      TunnelItem{T: ItemTunnel, Task: []byte{1}, Stream: 1, Host: "h", Port: 1},
		"tunnel, stream 0":        TunnelItem{T: ItemTunnel, Task: task, Host: "h", Port: 1},
		"tunnel, no host":         TunnelItem{T: ItemTunnel, Task: task, Stream: 1, Port: 1},
		"tunnel, port 0":          TunnelItem{T: ItemTunnel, Task: task, Stream: 1, Host: "h"},
		"tunnel, port 65536":      TunnelItem{T: ItemTunnel, Task: task, Stream: 1, Host: "h", Port: 65536},
		"tunnel, long host":       TunnelItem{T: ItemTunnel, Task: task, Stream: 1, Host: strings.Repeat("h", MaxTunnelHost+1), Port: 1},
		"tunnel, control in host": TunnelItem{T: ItemTunnel, Task: task, Stream: 1, Host: "h\x00st", Port: 1},
		"tunnel, host not UTF-8":  TunnelItem{T: ItemTunnel, Task: task, Stream: 1, Host: "\xff", Port: 1},
		"tunnel, room too big":    TunnelItem{T: ItemTunnel, Task: task, Stream: 1, Host: "h", Port: 1, Room: &big},
		"udp with a destination":  TunnelItem{T: ItemTunnel, Task: task, Stream: 1, Host: "h", Port: 53, UDP: true},
		"reply, negative result":  TunnelReplyItem{T: ItemTunnelReply, Task: task, Stream: 1, Result: -1},
		"reply, long bound":       TunnelReplyItem{T: ItemTunnelReply, Task: task, Stream: 1, Bound: strings.Repeat("1", MaxTunnelBound+1)},
		"reply, long msg":         TunnelReplyItem{T: ItemTunnelReply, Task: task, Stream: 1, Result: 6, Msg: strings.Repeat("m", MaxTunnelMsg+1)},
		"reply, stream 0":         TunnelReplyItem{T: ItemTunnelReply, Task: task},
		"data, nothing":           TunnelDataItem{T: ItemTunnelData, Task: task, Stream: 1, Off: 3},
		"data, too much":          TunnelDataItem{T: ItemTunnelData, Task: task, Stream: 1, Data: make([]byte, MaxTunnelData+1)},
		"data, past the end":      TunnelDataItem{T: ItemTunnelData, Task: task, Stream: 1, Off: math.MaxUint64, EOF: true},
		"ack, room too big":       TunnelAckItem{T: ItemTunnelAck, Task: task, Stream: 1, Room: &big},
		"ack, stream 0":           TunnelAckItem{T: ItemTunnelAck, Task: task},
		"close, no reason":        TunnelCloseItem{T: ItemTunnelClose, Task: task, Stream: 1},
		"close, msg not UTF-8":    TunnelCloseItem{T: ItemTunnelClose, Task: task, Stream: 1, Reason: 2, Msg: "\xff"},
		"datagram, no host":       TunnelDatagramItem{T: ItemTunnelDatagram, Task: task, Stream: 3, Port: 53},
		"datagram, port 0":        TunnelDatagramItem{T: ItemTunnelDatagram, Task: task, Stream: 3, Host: "h"},
		"datagram, too big":       TunnelDatagramItem{T: ItemTunnelDatagram, Task: task, Stream: 3, Host: "h", Port: 53, Data: make([]byte, MaxTunnelDatagram+1)},
	}
	for name, it := range bad {
		if err := it.Validate(); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
}

// An item's end counts its eof as one place, so an eof with no data is
// acked as received; a window not said is the default.
func TestTunnelOffsets(t *testing.T) {
	for _, c := range []struct {
		d    TunnelDataItem
		want uint64
	}{
		{TunnelDataItem{Off: 10, Data: []byte("abc")}, 13},
		{TunnelDataItem{Off: 13, EOF: true}, 14},
		{TunnelDataItem{Off: 0, Data: []byte("x"), EOF: true}, 2},
	} {
		if got := c.d.End(); got != c.want {
			t.Errorf("%+v: end %d, want %d", c.d, got, c.want)
		}
	}
	room := uint64(1024)
	if TunnelRoom(nil) != DefaultTunnelRoom || TunnelRoom(&room) != 1024 {
		t.Error("TunnelRoom")
	}
}

// Tunnel items travel as CBOR with their numbered keys, and come back as
// they went.
func TestTunnelItemsRoundTrip(t *testing.T) {
	task := bytes.Repeat([]byte{7}, 16)
	room := uint64(4096)
	in := TunnelItem{T: ItemTunnel, Task: task, Stream: 5, Host: "intranet", Port: 8443, Room: &room}
	b, err := MarshalCBOR(in)
	if err != nil {
		t.Fatal(err)
	}
	if ItemType(b) != ItemTunnel {
		t.Fatalf("type %d", ItemType(b))
	}
	var out TunnelItem
	if err := UnmarshalCBOR(b, &out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Task, task) || out.Stream != 5 || out.Host != "intranet" || out.Port != 8443 || out.Room == nil || *out.Room != 4096 || out.UDP {
		t.Errorf("came back as %+v", out)
	}
	d := TunnelDataItem{T: ItemTunnelData, Task: task, Stream: 5, Off: 7, Data: []byte{0, 1, 2}, EOF: true}
	if b, err = MarshalCBOR(d); err != nil {
		t.Fatal(err)
	}
	var back TunnelDataItem
	if err := UnmarshalCBOR(b, &back); err != nil || back.Off != 7 || !bytes.Equal(back.Data, d.Data) || !back.EOF || back.End() != 11 {
		t.Errorf("data came back as %+v (%v)", back, err)
	}
}

// Results and close reasons have names; one a later version has reads by
// its number.
func TestTunnelNames(t *testing.T) {
	for got, want := range map[string]string{
		TunnelResultName(TunnelOpen): "open", TunnelResultName(TunnelHostUnreachable): "host_unreachable",
		TunnelResultName(TunnelFailed): "failed", TunnelResultName(9): "result 9",
		TunnelCloseName(TunnelCloseDone): "done", TunnelCloseName(TunnelCloseTaskEnded): "task_ended",
		TunnelCloseName(0):   "reason 0",
		ItemName(ItemTunnel): "tunnel", ItemName(ItemTunnelReply): "tunnel_reply", ItemName(ItemTunnelData): "tunnel_data",
		ItemName(ItemTunnelAck): "tunnel_ack", ItemName(ItemTunnelClose): "tunnel_close", ItemName(ItemTunnelDatagram): "tunnel_datagram",
	} {
		if got != want {
			t.Errorf("name %q, want %q", got, want)
		}
	}
}

// A tunnel command takes core's port (an int) and names no result; its
// other params need defaults.
func TestTunnelAction(t *testing.T) {
	if a, ok := KnownAction(ActionTunnel); !ok || a.Result != "" || a.Params["port"] != FieldInt || len(a.Params) != 1 {
		t.Fatalf("tunnel: %+v %v", a, ok)
	}
	socks := BuildCommand{ID: "socks", Op: 9, Action: ActionTunnel, Params: []FieldSpec{
		{Key: "port", Num: 1, Type: FieldInt, Default: 0, Min: 0, Max: 65535},
		{Key: "timeout", Num: 2, Type: FieldDuration, Default: "10s"},
		{Key: "max_streams", Num: 3, Type: FieldInt, Default: 256}}}
	if err := validateResultAction(socks); err != nil {
		t.Errorf("tunnel: %v", err)
	}
	noDefault := socks
	noDefault.Params = []FieldSpec{socks.Params[0], {Key: "max_streams", Num: 3, Type: FieldInt}}
	if err := validateResultAction(noDefault); err == nil || !strings.Contains(err.Error(), "needs a default") {
		t.Errorf("a param without a default: %v", err)
	}
	withResult := socks
	withResult.Result = ResultDirListing
	if err := validateResultAction(withResult); err == nil || !strings.Contains(err.Error(), "has no result") {
		t.Errorf("tunnel with a result: %v", err)
	}
	noPort := socks
	noPort.Params = socks.Params[1:]
	if err := validateResultAction(noPort); err == nil || !strings.Contains(err.Error(), `"port"`) {
		t.Errorf("tunnel without port: %v", err)
	}
}
