package protocol

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// A VPN's routes are networks a minion's host may reach: CIDRs, none twice,
// no host bits, nothing of the machine's own (a default route, loopback,
// link-local, multicast).
func TestTunnelRoutes(t *testing.T) {
	got, err := TunnelRoutes([]string{"10.0.0.0/24", " 172.16.0.0/12", "fd00:1::/64", "10.0.0.5/32"})
	if err != nil || len(got) != 4 || got[1] != netip.MustParsePrefix("172.16.0.0/12") {
		t.Fatalf("routes: %v %v", got, err)
	}
	if !TunnelRouted(got, netip.MustParseAddr("10.0.0.77")) || !TunnelRouted(got, netip.MustParseAddr("::ffff:10.0.0.9")) ||
		!TunnelRouted(got, netip.MustParseAddr("fd00:1::5")) || TunnelRouted(got, netip.MustParseAddr("10.0.1.1")) {
		t.Error("routed")
	}
	many := make([]string, MaxTunnelRoutes+1)
	for i := range many {
		many[i] = netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i), 0, 0}), 16).String()
	}
	for name, c := range map[string]struct {
		routes []string
		want   string
	}{
		"none":         {nil, "a network at least"},
		"too many":     {many, "64 at most"},
		"no CIDR":      {[]string{"10.0.0.1"}, "not a network as a CIDR"},
		"a name":       {[]string{"corp.local/24"}, "not a network as a CIDR"},
		"host bits":    {[]string{"10.0.0.5/24"}, "the network is 10.0.0.0/24"},
		"default":      {[]string{"0.0.0.0/0"}, "default route"},
		"v6 default":   {[]string{"::/0"}, "default route"},
		"loopback":     {[]string{"127.0.0.0/8"}, "loopback"},
		"a wide one":   {[]string{"96.0.0.0/3"}, "holds 127.0.0.0/8"},
		"link-local":   {[]string{"169.254.0.0/16"}, "link-local"},
		"metadata":     {[]string{"169.0.0.0/8"}, "holds 169.254.0.0/16"},
		"multicast":    {[]string{"224.0.0.0/4"}, "multicast"},
		"v6 multicast": {[]string{"ff02::/16"}, "multicast"},
		"v6 loopback":  {[]string{"::1/128"}, "loopback"},
		"4in6":         {[]string{"::ffff:10.0.0.0/120"}, "write it as IPv4"},
		"twice":        {[]string{"10.0.0.0/24", "10.0.0.0/24"}, "10.0.0.0/24 twice"},
	} {
		if _, err := TunnelRoutes(c.routes); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

// A VPN tunnel takes its routes and no port; its source is a connection's,
// as the other fronts'.
func TestTunnelVPNParams(t *testing.T) {
	params := TunnelCoreParams(ActionTunnel)
	if _, problems := TaskArgs(params, map[string]any{ParamFront: FrontVPN}); problems[ParamRoutes] != "value is required" {
		t.Errorf("a vpn without routes: %v", problems)
	}
	args, problems := TaskArgs(params, map[string]any{ParamFront: FrontVPN, ParamRoutes: []any{"10.0.0.0/24"},
		ParamSource: "10.0.0.7"})
	if problems != nil || args[ParamPort] != nil || args[ParamSource] != "10.0.0.7" || args[ParamRoutes] == nil {
		t.Errorf("a vpn: %v %v", args, problems)
	}
	if _, problems = TaskArgs(params, map[string]any{ParamFront: FrontVPN, ParamRoutes: []any{"10.0.0.0/24"}, ParamPort: 41000}); problems[ParamPort] !=
		"only when front is socks, http, forward or terminal" {
		t.Errorf("a vpn's port: %v", problems)
	}
	if _, problems = TaskArgs(params, map[string]any{ParamRoutes: []any{"10.0.0.0/24"}}); problems[ParamRoutes] != "only when front is vpn" {
		t.Errorf("a socks proxy's routes: %v", problems)
	}
	// What a command opens may name icmp, a tunnel's alone.
	c := BuildCommand{ID: "tunnel", Op: 15, Action: ActionTunnel, Opens: []string{OpenTCP, OpenUDP, OpenICMP}}
	if err := validateBuildCommand(c, nil); err != nil {
		t.Errorf("a tunnel that opens icmp: %v", err)
	}
	c = BuildCommand{ID: "back", Op: 17, Action: ActionReverseTunnel, Opens: []string{OpenICMP},
		Params: []FieldSpec{{Key: "bind", Num: 1, Type: FieldString, Default: "0.0.0.0"}, {Key: "listen", Num: 2, Type: FieldInt, Default: 0},
			{Key: "udp", Num: 3, Type: FieldBool, Default: false}}}
	if err := validateBuildCommand(c, nil); err == nil || !strings.Contains(err.Error(), "icmp") {
		t.Errorf("a reverse tunnel that opens icmp: %v", err)
	}
}

// An icmp stream names no host, port or path: each datagram names its host,
// port 0. An open of kind 5 reads strictly.
func TestTunnelICMPOpen(t *testing.T) {
	task := bytes.Repeat([]byte{7}, 16)
	open := TunnelItem{T: ItemTunnel, Task: task, Stream: 3, Kind: TunnelKindICMP}
	if err := open.Validate(); err != nil {
		t.Fatalf("an icmp stream: %v", err)
	}
	raw, _ := MarshalCBOR(open)
	if it, err := ReadTunnel(raw); err != nil || it.Kind != TunnelKindICMP {
		t.Errorf("read: %+v %v", it, err)
	}
	for name, f := range map[string]func(*TunnelItem){
		"a host":   func(i *TunnelItem) { i.Host = "10.0.0.5" },
		"a port":   func(i *TunnelItem) { i.Port = 7 },
		"a path":   func(i *TunnelItem) { i.Path = "/x" },
		"udp":      func(i *TunnelItem) { i.UDP = true },
		"a source": func(i *TunnelItem) { i.Source = "10.0.0.7" },
		"tls":      func(i *TunnelItem) { i.TLS = true },
		"a size":   func(i *TunnelItem) { i.Rows, i.Cols = 24, 80 },
		"kind 6":   func(i *TunnelItem) { i.Kind = 6 },
	} {
		it := open
		f(&it)
		if it.Validate() == nil {
			t.Errorf("%s: valid", name)
		}
	}
	dg := TunnelDatagramItem{T: ItemTunnelDatagram, Task: task, Stream: 3, Host: "10.0.0.5", Data: []byte{8, 0, 0, 0, 0, 1, 0, 1}}
	if err := dg.Validate(); err != nil {
		t.Errorf("an icmp datagram, port 0: %v", err)
	}
	if dg.Host = ""; dg.Validate() == nil {
		t.Error("an icmp datagram with no host: valid")
	}
}

// An icmp stream's datagrams: echoes with their identifier, sequence and
// payload, and errors quoting the echo they answer; IPv4's checksum filled
// in, ICMPv6's types by the host's family.
func TestICMPMessages(t *testing.T) {
	echo := ICMPMessage{Type: ICMPEchoRequest, ID: 0x1234, Seq: 7, Payload: []byte("abcdefgh")}
	b := echo.Bytes(false)
	if len(b) != 16 || b[0] != 8 || ICMPChecksum(b) != 0 {
		t.Fatalf("an echo request: % x (checksum over it %x)", b, ICMPChecksum(b))
	}
	got, err := ReadICMP(b, false)
	if err != nil || got.ID != 0x1234 || got.Seq != 7 || string(got.Payload) != "abcdefgh" || !got.IsEcho(false) {
		t.Errorf("read back: %+v %v", got, err)
	}
	unreach := ICMPMessage{Type: ICMPDestUnreachable, Code: ICMPHostUnreachable, Quoted: &echo}
	b = unreach.Bytes(false)
	if len(b) != 16 || ICMPChecksum(b) != 0 {
		t.Errorf("an unreachable: % x", b)
	}
	got, err = ReadICMP(b, false)
	if err != nil || !got.IsError(false) || got.Code != 1 || got.Quoted == nil || got.Quoted.Seq != 7 || got.Quoted.ID != 0x1234 {
		t.Errorf("an unreachable read back: %+v %v", got, err)
	}
	// ICMPv6: its own types; type 3 is a time exceeded there.
	v6 := ICMPMessage{Type: ICMPv6EchoRequest, ID: 1, Seq: 2}
	exceeded := ICMPMessage{Type: ICMPv6TimeExceeded, Quoted: &v6}
	if got, err = ReadICMP(exceeded.Bytes(true), true); err != nil || got.Type != ICMPv6TimeExceeded || got.Quoted.Seq != 2 {
		t.Errorf("a v6 time exceeded: %+v %v", got, err)
	}
	if _, err = ReadICMP(exceeded.Bytes(true), false); err == nil {
		t.Error("a v6 message read as IPv4's")
	}
	for name, data := range map[string][]byte{
		"short":                   {8, 0, 0},
		"a timestamp":             {13, 0, 0, 0, 0, 0, 0, 0},
		"an error quoting little": {3, 1, 0, 0, 0, 0, 0, 0, 8, 0},
		"an error quoting a reply": ICMPMessage{Type: ICMPDestUnreachable,
			Quoted: &ICMPMessage{Type: ICMPEchoReply}}.Bytes(false),
	} {
		if _, err := ReadICMP(data, false); err == nil {
			t.Errorf("%s: read", name)
		}
	}
}

// The link's binary frames are tunnel items, as messages carry them; its
// hello says the link's version, the client's system and its instance.
func TestVPNLink(t *testing.T) {
	task := bytes.Repeat([]byte{7}, 16)
	a, _ := MarshalCBOR(TunnelItem{T: ItemTunnel, Task: task, Stream: 1, Host: "10.0.0.5", Port: 445})
	d, _ := MarshalCBOR(TunnelDataItem{T: ItemTunnelData, Task: task, Stream: 1, Data: []byte("x")})
	frame, err := VPNFrame([]cbor.RawMessage{a, d})
	if err != nil {
		t.Fatal(err)
	}
	items, err := ReadVPNFrame(frame)
	if err != nil || len(items) != 2 || ItemType(items[0]) != ItemTunnel || ItemType(items[1]) != ItemTunnelData {
		t.Fatalf("read: %d items %v", len(items), err)
	}
	if it, err := ReadTunnel(items[0]); err != nil || it.Port != 445 {
		t.Errorf("the open: %+v %v", it, err)
	}
	if _, err := VPNFrame(make([]cbor.RawMessage, MaxVPNFrameItems+1)); err == nil {
		t.Error("too many items")
	}
	big := make([]cbor.RawMessage, 9)
	for i := range big {
		big[i], _ = MarshalCBOR(TunnelDataItem{T: ItemTunnelData, Task: task, Stream: 1, Data: make([]byte, MaxTunnelData)})
	}
	if _, err := VPNFrame(big); err == nil {
		t.Error("a frame past its bytes")
	}
	if _, err := ReadVPNFrame([]byte{0xa1, 0x00, 0x01}); err == nil {
		t.Error("a map read as a frame")
	}
	hello := VPNHello{Link: VPNLink, Version: "v0.1.0", OS: "linux", Arch: "amd64", Machine: "kali",
		Instance: "00112233445566778899aabbccddeeff"}
	if err := hello.Validate(); err != nil {
		t.Errorf("hello: %v", err)
	}
	for name, f := range map[string]func(*VPNHello){
		"another link":     func(h *VPNHello) { h.Link = VPNLink + 1 },
		"no machine":       func(h *VPNHello) { h.Machine = " " },
		"a long version":   func(h *VPNHello) { h.Version = strings.Repeat("v", 65) },
		"a control":        func(h *VPNHello) { h.OS = "linux\n" },
		"a short instance": func(h *VPNHello) { h.Instance = "0011" },
		"no hex":           func(h *VPNHello) { h.Instance = strings.Repeat("zz", 16) },
	} {
		h := hello
		f(&h)
		if h.Validate() == nil {
			t.Errorf("%s: valid", name)
		}
	}
}
