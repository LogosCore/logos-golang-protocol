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
		"udp stream from a source":  TunnelItem{T: ItemTunnel, Task: task, Stream: 3, Host: "10.0.0.12", Port: 5353, UDP: true},
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
		"udp, a host alone":       TunnelItem{T: ItemTunnel, Task: task, Stream: 1, Host: "h", UDP: true},
		"udp, a port alone":       TunnelItem{T: ItemTunnel, Task: task, Stream: 1, Port: 53, UDP: true},
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

// A SOCKS proxy's command takes core's port (an int) and names no result;
// its other params need defaults.
func TestTunnelAction(t *testing.T) {
	if a, ok := KnownAction(ActionSocksProxy); !ok || a.Result != "" || a.Params["port"] != FieldInt || len(a.Params) != 1 {
		t.Fatalf("tunnel: %+v %v", a, ok)
	}
	socks := BuildCommand{ID: "socks", Op: 9, Action: ActionSocksProxy, Params: []FieldSpec{
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

// A port forward is a tunnel too: core gives port and reads host and to,
// which may be required (the action's own); the minion's other params need
// defaults; no result.
func TestForwardAction(t *testing.T) {
	if a, ok := KnownAction(ActionPortForward); !ok || a.Result != "" || a.Params["port"] != FieldInt || a.Params["host"] != FieldString ||
		a.Params["to"] != FieldInt || len(a.Params) != 3 {
		t.Fatalf("forward: %+v %v", a, ok)
	}
	if !IsTunnelAction(ActionSocksProxy) || !IsTunnelAction(ActionPortForward) || IsTunnelAction(ActionListDir) || IsTunnelAction("") ||
		IsTunnelAction("tunnel") {
		t.Error("IsTunnelAction")
	}
	forward := BuildCommand{ID: "forward", Op: 10, Action: ActionPortForward, Params: []FieldSpec{
		{Key: "port", Num: 1, Type: FieldInt, Default: 0, Min: 0, Max: 65535},
		{Key: "host", Num: 2, Type: FieldString, Required: true},
		{Key: "to", Num: 3, Type: FieldInt, Required: true, Min: 1, Max: 65535},
		{Key: "timeout", Num: 4, Type: FieldDuration, Default: "10s"}}}
	if err := validateResultAction(forward); err != nil {
		t.Errorf("forward: %v", err)
	}
	noHost := forward
	noHost.Params = []FieldSpec{forward.Params[0], forward.Params[2]}
	if err := validateResultAction(noHost); err == nil || !strings.Contains(err.Error(), `"host"`) {
		t.Errorf("forward without host: %v", err)
	}
	textPort := forward
	textPort.Params = []FieldSpec{forward.Params[0], forward.Params[1], {Key: "to", Num: 3, Type: FieldString}}
	if err := validateResultAction(textPort); err == nil || !strings.Contains(err.Error(), `"to"`) {
		t.Errorf("forward with a text to: %v", err)
	}
	noDefault := forward
	noDefault.Params = append(append([]FieldSpec{}, forward.Params[:3]...), FieldSpec{Key: "max_streams", Num: 5, Type: FieldInt})
	if err := validateResultAction(noDefault); err == nil || !strings.Contains(err.Error(), "needs a default") {
		t.Errorf("a minion's param without a default: %v", err)
	}
}

// A reverse port forward is a tunnel whose destination is core's alone:
// host and to carry no num (a num on either is refused, and none on the
// minion's own params), so a task's wire args never take them to the
// minion.
func TestReverseForwardAction(t *testing.T) {
	a, ok := KnownAction(ActionReversePortForward)
	if !ok || a.Result != "" || a.Params["bind"] != FieldString || a.Params["listen"] != FieldInt || a.Params["udp"] != FieldBool ||
		a.Params["host"] != FieldString || a.Params["to"] != FieldInt || len(a.Params) != 5 {
		t.Fatalf("reverse forward: %+v %v", a, ok)
	}
	if !IsTunnelAction(ActionReversePortForward) || !IsCoreParam(ActionReversePortForward, "host") ||
		!IsCoreParam(ActionReversePortForward, "to") || IsCoreParam(ActionReversePortForward, "bind") ||
		IsCoreParam(ActionPortForward, "host") || IsCoreParam("", "host") {
		t.Error("IsTunnelAction, IsCoreParam")
	}
	reverse := BuildCommand{ID: "reverse_port_forward", Op: 17, Action: ActionReversePortForward, Params: []FieldSpec{
		{Key: "bind", Num: 1, Type: FieldString, Default: "0.0.0.0"},
		{Key: "listen", Num: 2, Type: FieldInt, Required: true, Min: 0, Max: 65535},
		{Key: "udp", Num: 5, Type: FieldBool, Default: false},
		{Key: "host", Type: FieldString, Required: true},
		{Key: "to", Type: FieldInt, Required: true, Min: 1, Max: 65535},
		{Key: "timeout", Num: 3, Type: FieldDuration, Default: "10s"},
		{Key: "max_streams", Num: 4, Type: FieldInt, Default: 256}}}
	if err := validateResultAction(reverse); err != nil {
		t.Errorf("reverse forward: %v", err)
	}
	if err := validateCommandNumbers(reverse); err != nil {
		t.Errorf("reverse forward's numbers: %v", err)
	}
	numbered := reverse
	numbered.Params = append([]FieldSpec{}, reverse.Params...)
	numbered.Params[3].Num = 6
	if err := validateCommandNumbers(numbered); err == nil || !strings.Contains(err.Error(), "takes no num") {
		t.Errorf("a numbered destination: %v", err)
	}
	unnumbered := reverse
	unnumbered.Params = append([]FieldSpec{}, reverse.Params...)
	unnumbered.Params[0].Num = 0
	if err := validateCommandNumbers(unnumbered); err == nil || !strings.Contains(err.Error(), `"bind"`) {
		t.Errorf("an unnumbered bind: %v", err)
	}
	// A forward's host is the minion's, numbered as ever.
	forward := BuildCommand{ID: "forward", Op: 10, Action: ActionPortForward, Params: []FieldSpec{{Key: "host", Type: FieldString}}}
	if err := validateCommandNumbers(forward); err == nil {
		t.Error("an unnumbered forward host taken")
	}
	wire := WireArgs(reverse.Params, map[string]any{"bind": "0.0.0.0", "listen": int64(8080), "udp": true, "host": "10.8.0.2",
		"to": int64(4444), "timeout": int64(10000), "max_streams": int64(256)})
	if len(wire) != 5 || wire[1] != "0.0.0.0" || wire[2] != int64(8080) {
		t.Errorf("wire args %v", wire)
	}
	if udp, ok := ArgBool(wire, uint64(5)); !ok || !udp {
		t.Errorf("udp %v %v", udp, ok)
	}
	if _, ok := ArgBool(map[string]any{"udp": "yes"}, "udp"); ok {
		t.Error("a text read as a bool")
	}
	for _, v := range wire {
		if v == "10.8.0.2" || v == int64(4444) {
			t.Errorf("the destination went to the minion: %v", wire)
		}
	}
}

// tunnel_listen says where the minion listens: an ip:port, within its
// bound; TunnelListen checks a reverse forward's bind and listen.
func TestTunnelListen(t *testing.T) {
	id := make([]byte, 16)
	for _, c := range []struct {
		it   TunnelListenItem
		want string
	}{
		{TunnelListenItem{T: ItemTunnelListen, Task: id, Bound: "0.0.0.0:8080"}, ""},
		{TunnelListenItem{T: ItemTunnelListen, Task: id, Bound: "[::]:8080"}, ""},
		{TunnelListenItem{T: ItemTunnelListen, Task: id[:4], Bound: "0.0.0.0:8080"}, "16 bytes"},
		{TunnelListenItem{T: ItemTunnelListen, Task: id}, "ip:port"},
		{TunnelListenItem{T: ItemTunnelListen, Task: id, Bound: "0.0.0.0"}, "ip:port"},
		{TunnelListenItem{T: ItemTunnelListen, Task: id, Bound: strings.Repeat("1", MaxTunnelBound) + ":1"}, "at most"},
	} {
		err := c.it.Validate()
		if (c.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%+v: %v, want %q", c.it, err, c.want)
		}
	}
	for _, c := range []struct {
		bind   string
		listen int64
		ok     bool
	}{
		{"0.0.0.0", 8080, true}, {"::", 0, true}, {"10.0.0.7", 65535, true}, {"host.local", 1, true},
		{"", 8080, false}, {"0.0.0.0", -1, false}, {"0.0.0.0", 65536, false}, {"a\nb", 1, false}, {strings.Repeat("a", 256), 1, false},
	} {
		if err := TunnelListen(c.bind, c.listen); (err == nil) != c.ok {
			t.Errorf("TunnelListen(%q, %d): %v", c.bind, c.listen, err)
		}
	}
}

// stop_idle is every tunnel action's optional, core-only param: a command
// may take it (a duration, no num) or leave it out, as factories built
// before it did; one of another type, or numbered, is refused, and a task
// never takes it to the minion.
func TestTunnelStopIdle(t *testing.T) {
	for _, action := range TunnelActions() {
		a, _ := KnownAction(action)
		if a.Optional[ParamStopIdle] != FieldDuration || !IsCoreParam(action, ParamStopIdle) {
			t.Fatalf("%s: %+v", action, a)
		}
	}
	if IsCoreParam(ActionListDir, ParamStopIdle) {
		t.Error("a list_dir's stop_idle is core's")
	}
	socks := BuildCommand{ID: "socks", Op: 9, Action: ActionSocksProxy, Params: []FieldSpec{
		{Key: "port", Num: 1, Type: FieldInt, Default: 0},
		{Key: ParamStopIdle, Type: FieldDuration, Default: "1h"},
		{Key: "timeout", Num: 2, Type: FieldDuration, Default: "10s"}}}
	if err := validateResultAction(socks); err != nil {
		t.Errorf("with stop_idle: %v", err)
	}
	if err := validateCommandNumbers(socks); err != nil {
		t.Errorf("with stop_idle, numbers: %v", err)
	}
	without := socks
	without.Params = []FieldSpec{socks.Params[0], socks.Params[2]}
	if err := validateResultAction(without); err != nil {
		t.Errorf("without stop_idle: %v", err)
	}
	noDefault := socks
	noDefault.Params = []FieldSpec{socks.Params[0], {Key: ParamStopIdle, Type: FieldDuration}}
	if err := validateResultAction(noDefault); err != nil {
		t.Errorf("a stop_idle with no default: %v", err)
	}
	wrongType := socks
	wrongType.Params = []FieldSpec{socks.Params[0], {Key: ParamStopIdle, Type: FieldInt, Default: 60}}
	if err := validateResultAction(wrongType); err == nil || !strings.Contains(err.Error(), "or none") {
		t.Errorf("an int stop_idle: %v", err)
	}
	numbered := socks
	numbered.Params = []FieldSpec{socks.Params[0], {Key: ParamStopIdle, Num: 3, Type: FieldDuration, Default: "1h"}}
	if err := validateCommandNumbers(numbered); err == nil || !strings.Contains(err.Error(), "takes no num") {
		t.Errorf("a numbered stop_idle: %v", err)
	}
	wire := WireArgs(socks.Params, map[string]any{"port": int64(0), ParamStopIdle: int64(3600000), "timeout": int64(10000)})
	if len(wire) != 2 {
		t.Errorf("stop_idle went to the minion: %v", wire)
	}
}
