package protocol

import (
	"bytes"
	"errors"
	"math"
	"slices"
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
		"tunnel, short task":        TunnelItem{T: ItemTunnel, Task: []byte{1}, Stream: 1, Host: "h", Port: 1},
		"tunnel, stream 0":          TunnelItem{T: ItemTunnel, Task: task, Host: "h", Port: 1},
		"tunnel, no host":           TunnelItem{T: ItemTunnel, Task: task, Stream: 1, Port: 1},
		"tunnel, port 0":            TunnelItem{T: ItemTunnel, Task: task, Stream: 1, Host: "h"},
		"tunnel, port 65536":        TunnelItem{T: ItemTunnel, Task: task, Stream: 1, Host: "h", Port: 65536},
		"tunnel, long host":         TunnelItem{T: ItemTunnel, Task: task, Stream: 1, Host: strings.Repeat("h", MaxTunnelHost+1), Port: 1},
		"tunnel, control in host":   TunnelItem{T: ItemTunnel, Task: task, Stream: 1, Host: "h\x00st", Port: 1},
		"tunnel, host not UTF-8":    TunnelItem{T: ItemTunnel, Task: task, Stream: 1, Host: "\xff", Port: 1},
		"tunnel, room too big":      TunnelItem{T: ItemTunnel, Task: task, Stream: 1, Host: "h", Port: 1, Room: &big},
		"udp, a host alone":         TunnelItem{T: ItemTunnel, Task: task, Stream: 1, Host: "h", UDP: true},
		"udp, a port alone":         TunnelItem{T: ItemTunnel, Task: task, Stream: 1, Port: 53, UDP: true},
		"reply, negative result":    TunnelReplyItem{T: ItemTunnelReply, Task: task, Stream: 1, Result: -1},
		"reply, long bound":         TunnelReplyItem{T: ItemTunnelReply, Task: task, Stream: 1, Bound: strings.Repeat("1", MaxTunnelBound+1)},
		"reply, long msg":           TunnelReplyItem{T: ItemTunnelReply, Task: task, Stream: 1, Result: 6, Msg: strings.Repeat("m", MaxTunnelMsg+1)},
		"reply, stream 0":           TunnelReplyItem{T: ItemTunnelReply, Task: task},
		"data, nothing":             TunnelDataItem{T: ItemTunnelData, Task: task, Stream: 1, Off: 3},
		"data, too much":            TunnelDataItem{T: ItemTunnelData, Task: task, Stream: 1, Data: make([]byte, MaxTunnelData+1)},
		"data, past the end":        TunnelDataItem{T: ItemTunnelData, Task: task, Stream: 1, Off: math.MaxUint64, EOF: true},
		"ack, room too big":         TunnelAckItem{T: ItemTunnelAck, Task: task, Stream: 1, Room: &big},
		"ack, stream 0":             TunnelAckItem{T: ItemTunnelAck, Task: task},
		"close, no reason":          TunnelCloseItem{T: ItemTunnelClose, Task: task, Stream: 1},
		"close, msg not UTF-8":      TunnelCloseItem{T: ItemTunnelClose, Task: task, Stream: 1, Reason: 2, Msg: "\xff"},
		"datagram, no host":         TunnelDatagramItem{T: ItemTunnelDatagram, Task: task, Stream: 3, Port: 53},
		"datagram, port past 65535": TunnelDatagramItem{T: ItemTunnelDatagram, Task: task, Stream: 3, Host: "h", Port: 70000},
		"datagram, too big":         TunnelDatagramItem{T: ItemTunnelDatagram, Task: task, Stream: 3, Host: "h", Port: 53, Data: make([]byte, MaxTunnelDatagram+1)},
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
		TunnelResultName(TunnelFailed): "failed", TunnelResultName(99): "result 99",
		TunnelResultName(TunnelNotFound): "not_found", TunnelResultName(TunnelDenied): "denied", TunnelResultName(TunnelInUse): "in_use",
		ItemName(ItemTunnelCtl): "tunnel_ctl", TunnelSignalName(TunnelSignalInterrupt): "interrupt", TunnelSignalName(TunnelSignalKill): "kill",
		TunnelSignalName(9):              "signal 9",
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

// A tunnel's command declares only what its minion reads, each with a
// default; core adds its own params (the front, the port, a forward's
// destination, the cap), which carry no num and which a factory may not
// declare. No result.
func TestTunnelAction(t *testing.T) {
	a, ok := KnownAction(ActionTunnel)
	if !ok || a.Result != "" || len(a.Params) != 0 {
		t.Fatalf("tunnel: %+v %v", a, ok)
	}
	var keys []string
	for _, p := range TunnelCoreParams(ActionTunnel) {
		keys = append(keys, p.Key)
		if p.Num != 0 || !IsCoreParam(ActionTunnel, p.Key) {
			t.Errorf("%s: num %d, core's %v", p.Key, p.Num, IsCoreParam(ActionTunnel, p.Key))
		}
	}
	if strings.Join(keys, ",") != "front,port,routes,host,to,path,source,tls,program,args,rows,cols,stop_idle,cap" {
		t.Errorf("core's params %v", keys)
	}
	front := TunnelCoreParams(ActionTunnel)[0]
	if front.Type != FieldEnum || front.Default != FrontSOCKS || len(front.Options) != 5 || front.Options[1].Value != FrontHTTP {
		t.Errorf("front %+v", front)
	}
	if !IsTunnelAction(ActionTunnel) || !IsTunnelAction(ActionReverseTunnel) || IsTunnelAction(ActionListDir) || IsTunnelAction("") ||
		IsTunnelAction("socks_proxy") || IsCoreParam(ActionTunnel, "timeout") || IsCoreParam("", ParamFront) {
		t.Error("IsTunnelAction, IsCoreParam")
	}
	tunnel := BuildCommand{ID: "tunnel", Op: 15, Action: ActionTunnel, Opens: []string{OpenTCP, OpenUDP}, Params: []FieldSpec{
		{Key: "timeout", Num: 2, Type: FieldDuration, Default: "10s"},
		{Key: "max_streams", Num: 3, Type: FieldInt, Default: 256}}}
	if err := validateResultAction(tunnel); err != nil {
		t.Errorf("tunnel: %v", err)
	}
	if err := validateCommandNumbers(tunnel); err != nil {
		t.Errorf("tunnel's numbers: %v", err)
	}
	noDefault := tunnel
	noDefault.Params = []FieldSpec{{Key: "max_streams", Num: 3, Type: FieldInt}}
	if err := validateResultAction(noDefault); err == nil || !strings.Contains(err.Error(), "needs a default") {
		t.Errorf("a param without a default: %v", err)
	}
	withResult := tunnel
	withResult.Result = ResultDirListing
	if err := validateResultAction(withResult); err == nil || !strings.Contains(err.Error(), "has no result") {
		t.Errorf("tunnel with a result: %v", err)
	}
	for _, key := range []string{ParamFront, ParamPort, ParamHost, ParamTo, ParamStopIdle, ParamCap} {
		own := tunnel
		own.Params = append([]FieldSpec{{Key: key, Num: 9, Type: FieldString, Default: "x"}}, tunnel.Params...)
		if err := validateResultAction(own); err == nil || !strings.Contains(err.Error(), "core's") {
			t.Errorf("a factory's %s: %v", key, err)
		}
	}
	// The minion gets its own params alone: no front, no port, no
	// destination, no cap.
	params := append(append([]FieldSpec{}, tunnel.Params...), TunnelCoreParams(ActionTunnel)...)
	wire := WireArgs(params, map[string]any{"timeout": int64(10000), "max_streams": int64(256), ParamStopIdle: int64(3600000),
		ParamFront: FrontForward, ParamPort: int64(41000), ParamHost: "10.0.0.5", ParamTo: int64(3389), ParamCap: int64(1 << 20)})
	if len(wire) != 2 || wire[2] != int64(10000) || wire[3] != int64(256) {
		t.Errorf("wire args %v", wire)
	}
}

// A reverse tunnel's command declares where its minion listens (bind,
// listen, udp: the minion's, numbered); core adds the destination, required,
// stop_idle and the cap, never the minion's to know. Its one front, forward,
// no param names.
func TestReverseTunnelAction(t *testing.T) {
	a, ok := KnownAction(ActionReverseTunnel)
	if !ok || a.Result != "" || a.Params["bind"] != FieldString || a.Params["listen"] != FieldInt || a.Params["udp"] != FieldBool ||
		len(a.Params) != 3 {
		t.Fatalf("reverse tunnel: %+v %v", a, ok)
	}
	var keys []string
	for _, p := range TunnelCoreParams(ActionReverseTunnel) {
		keys = append(keys, p.Key)
	}
	if strings.Join(keys, ",") != "host,to,stop_idle,cap" {
		t.Errorf("core's params %v", keys)
	}
	if host := TunnelCoreParams(ActionReverseTunnel)[0]; !host.Required || host.When != nil || host.Order != 4 {
		t.Errorf("host %+v", host)
	}
	if !IsCoreParam(ActionReverseTunnel, ParamHost) || !IsCoreParam(ActionReverseTunnel, ParamTo) || IsCoreParam(ActionReverseTunnel, "bind") ||
		IsCoreParam(ActionReverseTunnel, ParamPort) || IsCoreParam(ActionReverseTunnel, ParamFront) {
		t.Error("IsCoreParam")
	}
	reverse := BuildCommand{ID: "reverse_tunnel", Op: 17, Action: ActionReverseTunnel, Params: []FieldSpec{
		{Key: "bind", Num: 1, Type: FieldString, Default: "0.0.0.0"},
		{Key: "listen", Num: 2, Type: FieldInt, Required: true, Min: 0, Max: 65535},
		{Key: "udp", Num: 5, Type: FieldBool, Default: false},
		{Key: "timeout", Num: 3, Type: FieldDuration, Default: "10s"},
		{Key: "max_streams", Num: 4, Type: FieldInt, Default: 256}}}
	if err := validateResultAction(reverse); err != nil {
		t.Errorf("reverse tunnel: %v", err)
	}
	if err := validateCommandNumbers(reverse); err != nil {
		t.Errorf("reverse tunnel's numbers: %v", err)
	}
	noUDP := reverse
	noUDP.Params = append([]FieldSpec{}, reverse.Params[:2]...)
	if err := validateResultAction(noUDP); err == nil || !strings.Contains(err.Error(), `"udp"`) {
		t.Errorf("a reverse tunnel without udp: %v", err)
	}
	unnumbered := reverse
	unnumbered.Params = append([]FieldSpec{}, reverse.Params...)
	unnumbered.Params[0].Num = 0
	if err := validateCommandNumbers(unnumbered); err == nil || !strings.Contains(err.Error(), `"bind"`) {
		t.Errorf("an unnumbered bind: %v", err)
	}
	params := append(append([]FieldSpec{}, reverse.Params...), TunnelCoreParams(ActionReverseTunnel)...)
	wire := WireArgs(params, map[string]any{"bind": "0.0.0.0", "listen": int64(8080), "udp": true,
		ParamHost: "10.8.0.2", ParamTo: int64(4444), "timeout": int64(10000), "max_streams": int64(256)})
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

// Each tunnel action has its fronts, its default first; no other action
// has any.
func TestTunnelFronts(t *testing.T) {
	if f := TunnelFronts(ActionTunnel); strings.Join(f, ",") != "socks,http,forward,terminal,vpn" {
		t.Errorf("tunnel: %v", f)
	}
	if f := TunnelFronts(ActionReverseTunnel); strings.Join(f, ",") != "forward" {
		t.Errorf("reverse tunnel: %v", f)
	}
	if TunnelFronts(ActionListDir) != nil || TunnelCoreParams(ActionListDir) != nil {
		t.Error("list_dir has fronts")
	}
	// Each front's option says it, the default first; a reverse tunnel's
	// one front no param names.
	front := TunnelCoreParams(ActionTunnel)[0]
	for i, f := range TunnelFronts(ActionTunnel) {
		if front.Key != ParamFront || front.Options[i].Value != f || front.Options[i].Label == "" {
			t.Errorf("option %d %+v, want %s", i, front.Options[i], f)
		}
	}
	if slices.ContainsFunc(TunnelCoreParams(ActionReverseTunnel), func(p FieldSpec) bool { return p.Key == ParamFront }) {
		t.Error("a reverse tunnel's front is a param")
	}
}

// A tunnel's params apply by its front (When): a destination a forward's,
// a source a connection's (no terminal's), a program and its size a
// terminal's; what is seldom changed is Advanced. A reverse tunnel's params
// name no front. Core's params are valid params of a command's form.
func TestTunnelParamsByFront(t *testing.T) {
	want := map[string]string{
		ParamHost: "forward", ParamTo: "forward", ParamPath: "forward", ParamTLS: "forward",
		ParamSource: "socks,http,forward,vpn",
		ParamPort:   "socks,http,forward,terminal", ParamRoutes: "vpn",
		ParamProgram: "terminal", ParamArgs: "terminal", ParamRows: "terminal", ParamCols: "terminal",
	}
	advanced := func(params []FieldSpec) string {
		var keys []string
		for _, p := range params {
			if p.Advanced {
				keys = append(keys, p.Key)
			}
		}
		return strings.Join(keys, ",")
	}
	params := TunnelCoreParams(ActionTunnel)
	for _, p := range params {
		got := ""
		if p.When != nil {
			got = p.When.Key + ":" + strings.Join(p.When.Values, ",")
		}
		if w := want[p.Key]; (w == "" && got != "") || (w != "" && got != ParamFront+":"+w) {
			t.Errorf("%s: when %q, want %q", p.Key, got, w)
		}
	}
	if got := advanced(params); got != "source,rows,cols,stop_idle,cap" {
		t.Errorf("tunnel's advanced: %s", got)
	}
	reverse := TunnelCoreParams(ActionReverseTunnel)
	for _, p := range reverse {
		if p.When != nil {
			t.Errorf("reverse %s: when %+v", p.Key, *p.When)
		}
	}
	if got := advanced(reverse); got != "stop_idle,cap" {
		t.Errorf("reverse tunnel's advanced: %s", got)
	}
	for _, action := range TunnelActions() {
		for _, p := range TunnelCoreParams(action) {
			if err := checkFieldSpec(p, scopeBuild); err != nil {
				t.Errorf("%s %s: %v", action, p.Key, err)
			}
		}
		if err := validateParamConditions(TunnelCoreParams(action), nil); err != nil {
			t.Errorf("%s: %v", action, err)
		}
	}

	// A SOCKS proxy by the defaults: no destination, no terminal's size.
	keysOfArgs := func(args map[string]any) string {
		keys := make([]string, 0, len(args))
		for k := range args {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		return strings.Join(keys, ",")
	}
	args, problems := TaskArgs(params, map[string]any{})
	if problems != nil || keysOfArgs(args) != "cap,front,port,stop_idle" {
		t.Errorf("socks: %v %v", args, problems)
	}
	_, problems = TaskArgs(params, map[string]any{ParamHost: "10.0.0.5", ParamRows: 30})
	if problems[ParamHost] != "only when front is forward" || problems[ParamRows] != "only when front is terminal" {
		t.Errorf("a socks proxy's destination, rows: %v", problems)
	}
	_, problems = TaskArgs(params, map[string]any{ParamFront: FrontTerminal, ParamSource: "10.0.0.7"})
	if problems[ParamSource] != "only when front is socks, http, forward or vpn" {
		t.Errorf("a terminal's source: %v", problems)
	}
	args, problems = TaskArgs(params, map[string]any{ParamFront: FrontTerminal})
	if problems != nil || args[ParamRows] != int64(24) || args[ParamCols] != int64(80) || args[ParamTLS] != nil {
		t.Errorf("a terminal: %v %v", args, problems)
	}
	args, problems = TaskArgs(params, map[string]any{ParamFront: FrontForward, ParamHost: "10.0.0.5", ParamTo: 3389})
	if problems != nil || args[ParamTLS] != false || args[ParamRows] != nil || args[ParamHost] != "10.0.0.5" {
		t.Errorf("a forward: %v %v", args, problems)
	}
	// A reverse tunnel's destination is required; no front is its param.
	_, problems = TaskArgs(reverse, map[string]any{ParamFront: FrontForward})
	if problems[ParamFront] != "not a declared field" || problems[ParamHost] != "value is required" || problems[ParamTo] != "value is required" {
		t.Errorf("a reverse tunnel's front, destination: %v", problems)
	}
}

// A tunnel command says what it opens (TCP alone when it says nothing); no
// other command says it, and nothing but tcp and udp, once each.
func TestTunnelOpens(t *testing.T) {
	targets := map[string]bool{}
	tunnel := BuildCommand{ID: "tunnel", Op: 15, Action: ActionTunnel}
	if !tunnel.CanOpen(OpenTCP) || tunnel.CanOpen(OpenUDP) {
		t.Error("a command that says nothing opens TCP alone")
	}
	tunnel.Opens = []string{OpenTCP, OpenUDP}
	if !tunnel.CanOpen(OpenUDP) || tunnel.CanOpen("unix") {
		t.Error("CanOpen")
	}
	if err := validateBuildCommand(tunnel, targets); err != nil {
		t.Errorf("tcp and udp: %v", err)
	}
	for name, c := range map[string]struct {
		cmd  BuildCommand
		want string
	}{
		"not a tunnel": {BuildCommand{ID: "ls", Op: 4, Action: ActionListDir, Result: ResultDirListing,
			Params: []FieldSpec{{Key: "path", Num: 1, Type: FieldString}}, Opens: []string{OpenTCP}}, "only a tunnel"},
		"unknown": {BuildCommand{ID: "tunnel", Op: 15, Action: ActionTunnel, Opens: []string{"sctp"}}, `"sctp" is not one`},
		"a reverse tunnel's pipe": {BuildCommand{ID: "reverse_tunnel", Op: 17, Action: ActionReverseTunnel,
			Params: []FieldSpec{{Key: "bind", Num: 1, Type: FieldString, Default: "0.0.0.0"}, {Key: "listen", Num: 2, Type: FieldInt, Default: 0},
				{Key: "udp", Num: 3, Type: FieldBool, Default: false}}, Opens: []string{OpenPipe}}, `"pipe" is not one of tcp, udp`},
		"duplicate": {BuildCommand{ID: "tunnel", Op: 15, Action: ActionTunnel, Opens: []string{OpenUDP, OpenUDP}}, "duplicate"},
	} {
		if err := validateBuildCommand(c.cmd, targets); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

// An open is read strictly: a key past this version's is refused
// (ErrTunnelUnsupported), never misread as a plain connect; one that does
// not read or validate says why; both keep the task and stream to answer
// with.
func TestReadTunnel(t *testing.T) {
	task := bytes.Repeat([]byte{7}, 16)
	enc := func(m map[int]any) []byte {
		t.Helper()
		b, err := MarshalCBOR(m)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	it, err := ReadTunnel(enc(map[int]any{0: ItemTunnel, 1: task, 2: 3, 3: "10.0.0.5", 4: 445, 5: 1024, 6: false}))
	if err != nil || it.Host != "10.0.0.5" || it.Port != 445 || TunnelRoom(it.Room) != 1024 || !it.Answerable() {
		t.Errorf("an open: %+v %v", it, err)
	}
	// A later version's keys (14, 15).
	it, err = ReadTunnel(enc(map[int]any{0: ItemTunnel, 1: task, 2: 4, 3: "10.0.0.5", 4: 443, 14: true, 15: "x"}))
	if !errors.Is(err, ErrTunnelUnsupported) || !it.Answerable() || it.Stream != 4 || it.Host != "" {
		t.Errorf("a later open: %+v %v", it, err)
	}
	// One that names a path, no host: it does not validate, and is
	// answered.
	it, err = ReadTunnel(enc(map[int]any{0: ItemTunnel, 1: task, 2: 5, 4: 1}))
	if err == nil || errors.Is(err, ErrTunnelUnsupported) || !it.Answerable() {
		t.Errorf("an open with no host: %+v %v", it, err)
	}
	// A port that is text: it does not read, and is still answered.
	it, err = ReadTunnel(enc(map[int]any{0: ItemTunnel, 1: task, 2: 6, 3: "h", 4: "445"}))
	if err == nil || !it.Answerable() {
		t.Errorf("a text port: %+v %v", it, err)
	}
	// No task: not answerable.
	if it, err = ReadTunnel(enc(map[int]any{0: ItemTunnel, 2: 7, 3: "h", 4: 1})); err == nil || it.Answerable() {
		t.Errorf("no task: %+v %v", it, err)
	}
	if _, err := ReadTunnel([]byte{0xff}); err == nil {
		t.Error("garbage read")
	}
	if TunnelResultName(TunnelUnsupported) != "unsupported" {
		t.Error("unsupported's name")
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

// stop_idle is a param core adds to every tunnel command, its default the
// action's (a tunnel 1h, a reverse tunnel never), just before the cap: a
// duration, no num, never the minion's. A factory declares it no more.
func TestTunnelStopIdle(t *testing.T) {
	for action, want := range map[string]string{ActionTunnel: "1h", ActionReverseTunnel: "0s"} {
		params := TunnelCoreParams(action)
		i := slices.IndexFunc(params, func(p FieldSpec) bool { return p.Key == ParamStopIdle })
		if i < 0 || i != len(params)-2 || params[i].Type != FieldDuration || params[i].Default != want || params[i].Num != 0 ||
			params[i].Order >= params[i+1].Order || !IsCoreParam(action, ParamStopIdle) {
			t.Fatalf("%s: %+v", action, params)
		}
	}
	if IsCoreParam(ActionListDir, ParamStopIdle) {
		t.Error("a list_dir's stop_idle is core's")
	}
	tunnel := BuildCommand{ID: "tunnel", Op: 9, Action: ActionTunnel, Params: []FieldSpec{
		{Key: "timeout", Num: 2, Type: FieldDuration, Default: "10s"}}}
	declared := tunnel
	declared.Params = append([]FieldSpec{{Key: ParamStopIdle, Type: FieldDuration, Default: "1h"}}, tunnel.Params...)
	if err := validateResultAction(declared); err == nil || !strings.Contains(err.Error(), "core's") {
		t.Errorf("a factory's stop_idle: %v", err)
	}
	params := append(append([]FieldSpec{}, tunnel.Params...), TunnelCoreParams(ActionTunnel)...)
	wire := WireArgs(params, map[string]any{ParamStopIdle: int64(3600000), "timeout": int64(10000)})
	if len(wire) != 1 {
		t.Errorf("stop_idle went to the minion: %v", wire)
	}
}

// An open of a unix socket or a pipe names its kind and path, no host or
// port; a source and TLS are a TCP connection's; a path's kind is a pipe's
// when it starts "\\".
func TestTunnelKinds(t *testing.T) {
	task := bytes.Repeat([]byte{7}, 16)
	open := func(f func(*TunnelItem)) TunnelItem {
		it := TunnelItem{T: ItemTunnel, Task: task, Stream: 1}
		f(&it)
		return it
	}
	for name, it := range map[string]TunnelItem{
		"a unix socket":       open(func(i *TunnelItem) { i.Kind, i.Path = TunnelKindUnix, "/var/run/docker.sock" }),
		"an abstract socket":  open(func(i *TunnelItem) { i.Kind, i.Path = TunnelKindUnix, "@/tmp/.X11-unix/X0" }),
		"a Windows socket":    open(func(i *TunnelItem) { i.Kind, i.Path = TunnelKindUnix, `C:\Users\x\agent.sock` }),
		"a local pipe":        open(func(i *TunnelItem) { i.Kind, i.Path = TunnelKindPipe, `\\.\pipe\spoolss` }),
		"another host's pipe": open(func(i *TunnelItem) { i.Kind, i.Path = TunnelKindPipe, `\\dc01\PIPE\lsarpc` }),
		"from a source":       open(func(i *TunnelItem) { i.Host, i.Port, i.Source = "10.0.0.5", 445, "10.0.0.7" }),
		"TLS to it":           open(func(i *TunnelItem) { i.Host, i.Port, i.TLS = "intranet.corp", 443, true }),
		"the host's shell":    open(func(i *TunnelItem) { i.Kind, i.Rows, i.Cols = TunnelKindProcess, 24, 80 }),
		"a program, args":     open(func(i *TunnelItem) { i.Kind, i.Path, i.Args = TunnelKindProcess, "powershell.exe", []string{"-NoLogo"} }),
		"an accept":           open(func(i *TunnelItem) { i.Kind, i.Host = TunnelKindAccept, "0.0.0.0" }),
		"an accept's port":    open(func(i *TunnelItem) { i.Kind, i.Host, i.Port = TunnelKindAccept, "::", 2121 }),
	} {
		if err := it.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, it := range map[string]TunnelItem{
		"a kind past this version's": open(func(i *TunnelItem) { i.Kind, i.Path = 5, "/x" }),
		"a process and a host":       open(func(i *TunnelItem) { i.Kind, i.Host, i.Port = TunnelKindProcess, "h", 1 }),
		"a process with udp":         open(func(i *TunnelItem) { i.Kind, i.UDP = TunnelKindProcess, true }),
		"rows, no cols":              open(func(i *TunnelItem) { i.Kind, i.Rows = TunnelKindProcess, 24 }),
		"a socket's args":            open(func(i *TunnelItem) { i.Kind, i.Path, i.Args = TunnelKindUnix, "/x", []string{"a"} }),
		"a TCP terminal":             open(func(i *TunnelItem) { i.Host, i.Port, i.Rows, i.Cols = "h", 1, 24, 80 }),
		"an accept, no address":      open(func(i *TunnelItem) { i.Kind = TunnelKindAccept }),
		"an accept's path":           open(func(i *TunnelItem) { i.Kind, i.Host, i.Path = TunnelKindAccept, "0.0.0.0", "/x" }),
		"an accept past 65535":       open(func(i *TunnelItem) { i.Kind, i.Host, i.Port = TunnelKindAccept, "0.0.0.0", 70000 }),
		"an accept with TLS":         open(func(i *TunnelItem) { i.Kind, i.Host, i.TLS = TunnelKindAccept, "0.0.0.0", true }),
		"a socket and a host":        open(func(i *TunnelItem) { i.Kind, i.Path, i.Host, i.Port = TunnelKindUnix, "/x", "h", 1 }),
		"a path, no kind":            open(func(i *TunnelItem) { i.Host, i.Port, i.Path = "h", 1, "/x" }),
		"a kind, no path":            open(func(i *TunnelItem) { i.Kind = TunnelKindUnix }),
		"a pipe not in \\":           open(func(i *TunnelItem) { i.Kind, i.Path = TunnelKindPipe, "/tmp/pipe" }),
		"a pipe with no name":        open(func(i *TunnelItem) { i.Kind, i.Path = TunnelKindPipe, `\\.\pipe\` }),
		"a socket in the pipe space": open(func(i *TunnelItem) { i.Kind, i.Path = TunnelKindUnix, `\\.\pipe\x` }),
		"a control in a path":        open(func(i *TunnelItem) { i.Kind, i.Path = TunnelKindUnix, "/x\x00y" }),
		"a long path":                open(func(i *TunnelItem) { i.Kind, i.Path = TunnelKindUnix, "/"+strings.Repeat("a", MaxTunnelPath) }),
		"a source that is a name":    open(func(i *TunnelItem) { i.Host, i.Port, i.Source = "h", 1, "eth0" }),
		"a socket's source":          open(func(i *TunnelItem) { i.Kind, i.Path, i.Source = TunnelKindUnix, "/x", "10.0.0.7" }),
		"UDP with TLS":               open(func(i *TunnelItem) { i.UDP, i.TLS = true, true }),
	} {
		if err := it.Validate(); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
	if TunnelPathKind(`\\.\pipe\x`) != TunnelKindPipe || TunnelPathKind("/run/x.sock") != TunnelKindUnix || TunnelPathKind("@x") != TunnelKindUnix {
		t.Error("TunnelPathKind")
	}
	// Each reads back as it went.
	raw, err := MarshalCBOR(open(func(i *TunnelItem) { i.Kind, i.Path = TunnelKindPipe, `\\dc01\pipe\x` }))
	if err != nil {
		t.Fatal(err)
	}
	if it, err := ReadTunnel(raw); err != nil || it.Kind != TunnelKindPipe || it.Path != `\\dc01\pipe\x` {
		t.Errorf("a pipe read back: %+v %v", it, err)
	}
}

// A target narrows what its tunnel commands open: a Linux build has no
// pipes; one that says nothing has all of its commands'.
func TestCommandOpens(t *testing.T) {
	cmd := BuildCommand{ID: "tunnel", Op: 15, Action: ActionTunnel, Opens: []string{OpenTCP, OpenUDP, OpenUnix, OpenPipe, OpenSource, OpenTLS}}
	s := BuildSchema{Targets: []BuildTarget{{ID: "linux-elf", Opens: []string{OpenTCP, OpenUDP, OpenUnix, OpenSource, OpenTLS}}, {ID: "windows-exe"}},
		Commands: []BuildCommand{cmd}}
	if got := strings.Join(s.CommandOpens(cmd, "linux-elf"), ","); got != "tcp,udp,unix,source,tls" {
		t.Errorf("linux: %s", got)
	}
	if got := strings.Join(s.CommandOpens(cmd, "windows-exe"), ","); got != "tcp,udp,unix,pipe,source,tls" {
		t.Errorf("windows: %s", got)
	}
	if got := strings.Join(s.CommandOpens(BuildCommand{ID: "t", Action: ActionTunnel}, "windows-exe"), ","); got != "tcp" {
		t.Errorf("a command that says none: %s", got)
	}
	bad := BuildTarget{ID: "x", Format: "bin", Platforms: []string{"linux/amd64"}, Opens: []string{"sctp"}}
	if err := validateBuildTarget(bad, nil, nil); err == nil || !strings.Contains(err.Error(), `"sctp"`) {
		t.Errorf("an unknown open: %v", err)
	}
	bad.Opens = []string{OpenTCP, OpenTCP}
	if err := validateBuildTarget(bad, nil, nil); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("a duplicate open: %v", err)
	}
}

// A process's open: its program (none: the host's shell), its args, its
// terminal; an operator's command line splits as a shell's words do.
func TestTunnelProcess(t *testing.T) {
	for name, c := range map[string]struct {
		program    string
		args       []string
		rows, cols uint64
		want       string
	}{
		"the host's shell, a terminal": {"", nil, 24, 80, ""},
		"on pipes":                     {"/bin/cat", nil, 0, 0, ""},
		"args":                         {"bash", []string{"-l", "a b", ""}, 50, 200, ""},
		"args to the host's shell":     {"", []string{"-l"}, 24, 80, "with a program"},
		"cols, no rows":                {"sh", nil, 0, 80, "rows and cols"},
		"a huge terminal":              {"sh", nil, MaxTunnelTerm + 1, 80, "at most"},
		"a control in a program":       {"sh\n", nil, 0, 0, "control"},
		"a NUL in an arg":              {"sh", []string{"a\x00"}, 0, 0, "NUL"},
		"too many args":                {"sh", make([]string, MaxTunnelArgs+1), 0, 0, "at most"},
		"args too long":                {"sh", []string{strings.Repeat("a", MaxTunnelArgsBytes+1)}, 0, 0, "together"},
		"a long program":               {strings.Repeat("a", MaxTunnelPath+1), nil, 0, 0, "at most"},
	} {
		err := TunnelProcess(c.program, c.args, c.rows, c.cols)
		if (c.want == "") != (err == nil) || err != nil && !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	for line, want := range map[string][]string{
		"":                     nil,
		"  -l  ":               {"-l"},
		`-c 'echo $HOME; id'`:  {"-c", "echo $HOME; id"},
		`-c "a \"b\" c" d\ e`:  {"-c", `a "b" c`, "d e"},
		`''`:                   {""},
		`a'b'"c"`:              {"abc"},
		"-NoLogo\t-NoProfile":  {"-NoLogo", "-NoProfile"},
		`'C:\Program Files\x'`: {`C:\Program Files\x`},
	} {
		if got, err := TunnelArgs(line); err != nil || !slices.Equal(got, want) {
			t.Errorf("%q: %q %v, want %q", line, got, err, want)
		}
	}
	for _, bad := range []string{`'open`, `"open`, `end\`} {
		if _, err := TunnelArgs(bad); err == nil {
			t.Errorf("%q split", bad)
		}
	}
}

// tunnel_ctl says a size, a signal, an exit or who came, and reads back as
// it went; an ack's Ctl says how far the ctls are taken.
func TestTunnelCtl(t *testing.T) {
	task := bytes.Repeat([]byte{7}, 16)
	ctl := func(f func(*TunnelCtlItem)) TunnelCtlItem {
		c := TunnelCtlItem{T: ItemTunnelCtl, Task: task, Stream: 1}
		f(&c)
		return c
	}
	exit := int64(130)
	for name, c := range map[string]TunnelCtlItem{
		"a size":         ctl(func(c *TunnelCtlItem) { c.Rows, c.Cols = 50, 200 }),
		"an interrupt":   ctl(func(c *TunnelCtlItem) { c.Seq, c.Signal = 3, TunnelSignalInterrupt }),
		"an exit":        ctl(func(c *TunnelCtlItem) { c.Exit = &exit }),
		"an exit of 0":   ctl(func(c *TunnelCtlItem) { zero := int64(0); c.Exit = &zero }),
		"who came":       ctl(func(c *TunnelCtlItem) { c.Host, c.Port = "10.0.0.9", 50122 }),
		"a later signal": ctl(func(c *TunnelCtlItem) { c.Signal = 42 }),
	} {
		if err := c.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, c := range map[string]TunnelCtlItem{
		"nothing":      ctl(func(*TunnelCtlItem) {}),
		"rows alone":   ctl(func(c *TunnelCtlItem) { c.Rows = 50 }),
		"a huge size":  ctl(func(c *TunnelCtlItem) { c.Rows, c.Cols = 50, MaxTunnelTerm+1 }),
		"a host alone": ctl(func(c *TunnelCtlItem) { c.Host = "10.0.0.9" }),
		"a port alone": ctl(func(c *TunnelCtlItem) { c.Port = 1 }),
		"no stream":    ctl(func(c *TunnelCtlItem) { c.Stream, c.Signal = 0, 1 }),
		"a short task": ctl(func(c *TunnelCtlItem) { c.Task, c.Signal = task[:4], 1 }),
		"a minus sign": ctl(func(c *TunnelCtlItem) { c.Signal = -1 }),
	} {
		if err := c.Validate(); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
	raw, err := MarshalCBOR(ctl(func(c *TunnelCtlItem) { c.Seq, c.Exit = 2, &exit }))
	if err != nil {
		t.Fatal(err)
	}
	var back TunnelCtlItem
	if err := UnmarshalCBOR(raw, &back); err != nil || back.Seq != 2 || back.Exit == nil || *back.Exit != 130 || ItemType(raw) != ItemTunnelCtl {
		t.Errorf("read back: %+v %v", back, err)
	}
	// An exit of 0 is said, not dropped as empty.
	zero := int64(0)
	raw, _ = MarshalCBOR(ctl(func(c *TunnelCtlItem) { c.Exit = &zero }))
	back = TunnelCtlItem{}
	if err := UnmarshalCBOR(raw, &back); err != nil || back.Exit == nil || *back.Exit != 0 {
		t.Errorf("an exit of 0: %+v %v", back, err)
	}
}
