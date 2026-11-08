package protocol

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

// Task results and actions (docs: contracts/task-results-and-actions.md):
// the vocabulary a build command picks from, defined here and in core,
// the same for every factory. A command's result (BuildCommand.Result)
// says what its data is: its minion sends the data in that shape, and core
// checks the parts, joins them and shows them with the result's view. A
// command's action (BuildCommand.Action) says what core can ask it to do
// itself: the params core gives, and the result the command must have. A
// factory picks from these only: a name this version does not know is
// refused, so a typo shows when the factory starts, not as raw data.

// Results.
const (
	// ResultDirListing is one directory's entries (DirListing).
	ResultDirListing = "dir_listing"
	// ResultFileDownload is a file the minion sent core (FileDownload):
	// core keeps the file, the data says which one.
	ResultFileDownload = "file_download"
	// ResultFileUpload is a file core sent the minion (FileUpload): the
	// data says where it went.
	ResultFileUpload = "file_upload"
	// ResultFileStream is a file the minion streamed to whoever downloaded
	// it (FileStream): core keeps none of it, the data says which file.
	ResultFileStream = "file_stream"
	// ResultDirWalk is a walk through a directory and what is under it
	// (DirWalk): its listings go to core as they come (ResultItem.Ls), the
	// data says where it stands.
	ResultDirWalk = "dir_walk"
	// ResultVolumes is the host's volumes (Volumes): its drives, the file
	// systems it has mounted, each with where its files are.
	ResultVolumes = "volumes"
)

// Actions.
const (
	// ActionListDir lists a directory: core gives path; the command's
	// result is a ResultDirListing.
	ActionListDir = "list_dir"
	// ActionDownloadFile sends a file to core: core gives path; the
	// command's result is a ResultFileDownload.
	ActionDownloadFile = "download_file"
	// ActionUploadFile puts a file on the host: core gives path, file (a
	// task file) and overwrite; the command's result is a ResultFileUpload.
	ActionUploadFile = "upload_file"
	// ActionStreamFile streams a file to whoever downloads it: core gives
	// path; the command's result is a ResultFileStream.
	ActionStreamFile = "stream_file"
	// ActionUploadStream puts a file on the host streamed as it is
	// uploaded: core gives path, stream and overwrite; the command's result
	// is a ResultFileUpload.
	ActionUploadStream = "upload_stream"
	// ActionDeletePath removes a file, a link or a folder on the host: core
	// gives path and recursive (a folder with what is in it). It has no
	// result: the task's output says what went.
	ActionDeletePath = "delete_path"
	// ActionWalkDir lists a directory and the folders under it, as deep as
	// the command goes: core gives path; the command's result is a
	// ResultDirWalk.
	ActionWalkDir = "walk_dir"
	// ActionListVolumes lists the host's volumes: core gives nothing; the
	// command's result is a ResultVolumes. The file browser runs it for a
	// machine's roots (a Windows host's drives).
	ActionListVolumes = "list_volumes"
	// ActionSwitchConnection moves the minion to another of its build's
	// connections: core gives conn, its place in the build's connections,
	// from 1 (a param of FormatConnection, so the UI offers them by name). It has no result: the task's output says how it went, and a
	// minion that moved says so in a conn_update (ConnUpdateItem) over the
	// new connection. A command may take more (BOB's connect: for how long),
	// each with a default.
	ActionSwitchConnection = "switch_connection"
	// ActionTunnel lends the minion's host to streams core opens
	// (tunnels.go): each a connection the minion makes to where its tunnel
	// item says, or a UDP association. What core puts in front of them is
	// the task's front (ParamFront, TunnelFronts): its SOCKS proxy, its
	// HTTP proxy, or a port forward to one destination, on one of its
	// operational ports. Core adds its own params to every command of the
	// action (CommandAction.Adds: the front, the port, a forward's
	// destination, stop_idle, the bandwidth cap), which carry no num: the
	// minion needs nothing of them. A command declares what its minion
	// reads (a connect's timeout, its max_streams), each with a default.
	// No result: the task runs while the tunnel is open,
	// its streams going as tunnel items, and core shows it.
	ActionTunnel = "tunnel"
	// ActionReverseTunnel runs a tunnel the other way, as ssh -R does: the
	// minion listens on its host at bind:listen (listen 0: any free port)
	// and opens a stream for each connection that comes there; with udp,
	// it listens for datagrams, a stream for each address they come from.
	// Core connects each to host:to from its own network (a UDP one's
	// datagrams sent on there): a reverse port forward, its one front
	// (FrontForward), which no param names. A reverse SOCKS front was
	// dropped: a minion's holder would learn its password, which crosses
	// the minion in the clear, and reach all of core's network with it.
	// bind, listen and udp are the minion's, read from its task; host, to,
	// stop_idle and cap are core's alone (CommandAction.Adds), so the
	// minion never learns where core sends what comes. The same items, the streams the minion's
	// (tunnels.go); no result; more params, each with a default.
	ActionReverseTunnel = "reverse_tunnel"
)

// TunnelActions are the tunnel actions: a task of a command with one
// carries streams as tunnel items, whatever core puts in front of them.
// Such a task holds none of the minion's max_tasks: it runs as long as its
// tunnel is open, a minion's capability rather than its work, and both
// sides count it out. Core adds stop_idle (ParamStopIdle) to each, a
// duration it alone reads: core stops the task once no stream has been
// open for that long (0: never).
func TunnelActions() []string {
	return []string{ActionTunnel, ActionReverseTunnel}
}

// ParamStopIdle is a param core adds to every tunnel command
// (CommandAction.Adds): a duration (FieldDuration) after which, with no
// stream open, core stops the task as Stop does; 0 never. Its default is
// the action's: 1h for a tunnel, never for a reverse tunnel (one often
// waits hours for a callback).
const ParamStopIdle = "stop_idle"

// The params core adds to every tunnel command (CommandAction.Adds): the
// operator gives them as a tunnel starts, and the minion never sees them.
const (
	// ParamFront is what core puts in front of a tunnel's streams: one of
	// TunnelFronts(ActionTunnel), its first when none is given. A reverse
	// tunnel has none: its one front is forward.
	ParamFront = "front"
	// ParamPort is a tunnel's operational port: 0 for any free one.
	ParamPort = "port"
	// ParamHost and ParamTo are a forward's destination: from the minion's
	// host (a tunnel), or from core's network (a reverse tunnel).
	ParamHost = "host"
	ParamTo   = "to"
	// ParamCap is the tunnel's bandwidth cap: bytes a second each way, over
	// all of its streams together; 0 for none. Core changes it live.
	ParamCap = "cap"
	// ParamPath is a forward's destination when it is a unix socket's path
	// or a named pipe (TunnelPathKind), instead of a host and a port.
	ParamPath = "path"
	// ParamSource is the address of the minion's host a tunnel's TCP
	// connections go from; ParamTLS, TLS to a forward's destination.
	ParamSource = "source"
	ParamTLS    = "tls"
	// ParamProgram and ParamArgs are a terminal's program (none: the
	// host's shell) and its args, a command line core splits
	// (TunnelArgs); ParamRows and ParamCols its size on the raw port (the
	// web terminal says its own).
	ParamProgram = "program"
	ParamArgs    = "args"
	ParamRows    = "rows"
	ParamCols    = "cols"
	// ParamRoutes are a VPN's networks (FrontVPN): CIDRs the client routes
	// on the operator's machine (TunnelRoutes). Core changes them live.
	ParamRoutes = "routes"
)

// Tunnel fronts: what core puts in front of a tunnel task's streams, the
// operator's to pick as the task starts (ParamFront).
const (
	// FrontSOCKS: a tunnel's SOCKS proxy (5, 4 and 4a) on one of core's
	// operational ports. A reverse tunnel takes none.
	FrontSOCKS = "socks"
	// FrontHTTP: a tunnel's HTTP proxy (CONNECT, and plain requests) on one
	// of core's operational ports.
	FrontHTTP = "http"
	// FrontForward: every stream to one destination, host:to: from the
	// minion's host (a tunnel), or from core's network (a reverse tunnel).
	FrontForward = "forward"
	// FrontTerminal: a tunnel's process for each connection, a shell
	// unless the task says another program, in a terminal: in the web app,
	// or raw on one of core's operational ports.
	FrontTerminal = "terminal"
	// FrontVPN: a tunnel's VPN: logos-vpn, core's client on an operator's
	// machine, routes the machine into the task's routes (ParamRoutes),
	// each connection, UDP flow and ping it sees there a stream, over core's
	// own address (the VPN link, VPNPath): no operational port.
	FrontVPN = "vpn"
)

// TunnelFronts are the fronts a tunnel action takes, the one a task that
// names none gets first (a reverse tunnel's one, forward, it never names:
// it has no front param); nil for any other action.
func TunnelFronts(action string) []string {
	switch action {
	case ActionTunnel:
		return []string{FrontSOCKS, FrontHTTP, FrontForward, FrontTerminal, FrontVPN}
	case ActionReverseTunnel:
		return []string{FrontForward}
	}
	return nil
}

// What a tunnel command opens, and how (BuildCommand.Opens).
const (
	// OpenTCP: TCP connections (a tunnel), or a TCP listener (a reverse
	// tunnel).
	OpenTCP = "tcp"
	// OpenUDP: UDP associations (a tunnel's SOCKS UDP ASSOCIATE), or a UDP
	// listener (a reverse tunnel's udp).
	OpenUDP = "udp"
	// OpenUnix and OpenPipe: a tunnel's unix sockets and named pipes
	// (TunnelKindUnix, TunnelKindPipe).
	OpenUnix = "unix"
	OpenPipe = "pipe"
	// OpenSource: a tunnel's TCP connections from an address of the
	// minion's host (TunnelItem.Source); OpenTLS: TLS to the destination
	// (TunnelItem.TLS).
	OpenSource = "source"
	OpenTLS    = "tls"
	// OpenProcess: a tunnel's processes (TunnelKindProcess, its terminal
	// front); OpenAccept: its listeners for one connection
	// (TunnelKindAccept, SOCKS5 BIND).
	OpenProcess = "process"
	OpenAccept  = "accept"
	// OpenICMP: a tunnel's pings (TunnelKindICMP, its VPN front): echo
	// requests sent from the minion's host, and what answers them.
	OpenICMP = "icmp"
)

// opensOf is what a command of a tunnel action may say it opens.
func opensOf(action string) []string {
	switch action {
	case ActionTunnel:
		return []string{OpenTCP, OpenUDP, OpenUnix, OpenPipe, OpenSource, OpenTLS, OpenProcess, OpenAccept, OpenICMP}
	case ActionReverseTunnel:
		return []string{OpenTCP, OpenUDP}
	}
	return nil
}

// IsTunnelAction reports whether action is one of TunnelActions.
func IsTunnelAction(action string) bool { return slices.Contains(TunnelActions(), action) }

// TunnelCoreParams are the params core adds to every command of a tunnel
// action (CommandAction.Adds), none for any other: a copy, for core to put
// beside the command's own when it offers it.
func TunnelCoreParams(action string) []FieldSpec {
	return slices.Clone(actions[action].Adds)
}

// tunnelCoreParams are what core adds to a tunnel action's commands: a
// tunnel's front (fronts its options, the first the default) and port, a
// VPN's routes, a forward's destination, when core stops it idle
// (stop_idle) and the bandwidth cap. They carry no num. They come first in
// a tunnel's form, after where a reverse tunnel listens (its command's
// bind, listen and udp: orders 1 to 3), and stop_idle and the cap last; a
// command's own params take orders from 10. A tunnel's apply by its front
// (When): its port every front's but a VPN's (whose client comes over
// core's own address), its routes a VPN's, its destination a forward's
// alone, its program a terminal's. A reverse tunnel has one front, forward
// (fronts nil): no param names it, and its destination is required. What
// is seldom changed is Advanced.
func tunnelCoreParams(action string, fronts []EnumOption) []FieldSpec {
	reverse := action == ActionReverseTunnel
	order := 0
	if reverse {
		order = 3
	}
	next := func() int { order++; return order }
	on := func(values ...string) *FieldCondition {
		if reverse {
			return nil
		}
		return &FieldCondition{Key: ParamFront, Values: values}
	}
	host, to := "A forward's destination, reached from the minion's host: a name or an address.", "A forward's destination port."
	if reverse {
		host, to = "Where core connects each connection that comes, from its own network: a name or an address.", "The destination's port."
	}
	var out []FieldSpec
	if !reverse {
		out = append(out,
			FieldSpec{Key: ParamFront, Type: FieldEnum, Label: "Front", Default: fronts[0].Value, Options: fronts, Order: next(),
				Description: "What core puts in front of the tunnel."},
			FieldSpec{Key: ParamPort, Type: FieldInt, Label: "Port", Default: 0, Min: 0, Max: 65535, Order: next(),
				Description: "The operational port core listens on: 0 for any free one.",
				When:        on(FrontSOCKS, FrontHTTP, FrontForward, FrontTerminal)},
			FieldSpec{Key: ParamRoutes, Type: FieldStringList, Label: "Routes", Required: true, MaxItems: MaxTunnelRoutes,
				MaxLength: maxTunnelRoute, Order: next(),
				Description: "The networks logos-vpn routes on the operator's machine, as CIDRs (10.0.0.0/24, fd00:1::/64): every tool there reaches them through the minion. They can be changed while the tunnel runs.",
				When:        on(FrontVPN)})
	}
	out = append(out,
		FieldSpec{Key: ParamHost, Type: FieldString, Label: "Destination", Required: reverse, MaxLength: MaxTunnelHost, Order: next(),
			Description: host, When: on(FrontForward)},
		FieldSpec{Key: ParamTo, Type: FieldInt, Label: "Destination port", Required: reverse, Min: 1, Max: 65535, Order: next(),
			Description: to, When: on(FrontForward)})
	if !reverse {
		// What a tunnel's command opens decides which of these core offers.
		out = append(out,
			FieldSpec{Key: ParamPath, Type: FieldString, Label: "Destination path", MaxLength: MaxTunnelPath, Order: next(),
				Description: `A forward to a unix socket (/var/run/docker.sock, @name) or a named pipe (\\.\pipe\name, \\host\pipe\name), instead of a host and a port.`,
				When:        on(FrontForward)},
			FieldSpec{Key: ParamSource, Type: FieldString, Label: "Source address", MaxLength: 64, Order: next(), Advanced: true,
				Description: "An address of the minion's host its connections go from, on a host with two networks: none, as the host routes.",
				When:        on(FrontSOCKS, FrontHTTP, FrontForward, FrontVPN)},
			FieldSpec{Key: ParamTLS, Type: FieldBool, Label: "TLS to the destination", Default: false, Order: next(),
				Description: "The minion speaks TLS to the destination (it checks no certificate), the tools plain: a host and a port's, not a path's.",
				When:        on(FrontForward)},
			FieldSpec{Key: ParamProgram, Type: FieldString, Label: "Program", MaxLength: MaxTunnelPath, Order: next(),
				Description: "On the minion's host's PATH (bash, powershell.exe): none, the host's shell.", When: on(FrontTerminal)},
			FieldSpec{Key: ParamArgs, Type: FieldString, Label: "Args", MaxLength: MaxTunnelArgsBytes, Order: next(),
				Description: `The program's args, a command line ('quoted words' kept as they are).`, When: on(FrontTerminal)},
			FieldSpec{Key: ParamRows, Type: FieldInt, Label: "Rows", Default: 24, Min: 1, Max: MaxTunnelTerm, Order: next(), Advanced: true,
				Description: "The terminal's rows on the raw port: the web terminal says its own.", When: on(FrontTerminal)},
			FieldSpec{Key: ParamCols, Type: FieldInt, Label: "Columns", Default: 80, Min: 1, Max: MaxTunnelTerm, Order: next(), Advanced: true,
				Description: "The terminal's columns on the raw port.", When: on(FrontTerminal)})
	}
	idle, idleNote := "1h", "Core stops the tunnel once no connection has been open this long: 0s never."
	if reverse {
		idle, idleNote = "0s", "Core stops the tunnel once no connection has been open this long: 0s never, the default: a reverse tunnel often waits for a callback."
	}
	return append(out,
		FieldSpec{Key: ParamStopIdle, Type: FieldDuration, Label: "Stop when idle for", Default: idle, Order: 999, Advanced: true, Description: idleNote},
		FieldSpec{Key: ParamCap, Type: FieldBytes, Label: "Bandwidth cap", Default: 0, Min: 0, Unit: "B/s", Order: 1000, Advanced: true,
			Description: "Bytes a second each way, over all of the tunnel's streams: 0 for none. It can be changed while the tunnel runs."})
}

// results are the results this version defines.
var results = map[string]bool{
	ResultDirListing:   true,
	ResultFileDownload: true,
	ResultFileUpload:   true,
	ResultFileStream:   true,
	ResultDirWalk:      true,
	ResultVolumes:      true,
}

// CommandAction is an action's contract: the params core gives when it runs a
// command of the action (each of a type), and the result the command's data
// must be, so what core does with it next works (a folder listed opens in
// the file browser).
type CommandAction struct {
	Params map[string]FieldType
	Result string
	// Adds are params core adds to every command of the action, beside the
	// command's own (a tunnel's front, port, destination, stop_idle and
	// cap): a factory declares none of them, they carry no num, so a task
	// never takes them to the minion, and core reads them alone.
	Adds []FieldSpec
}

// IsCoreParam reports whether key is core's alone in action's commands: a
// param core adds (Adds). It has no num, and never goes to the minion.
func IsCoreParam(action, key string) bool {
	a, ok := actions[action]
	return ok && slices.ContainsFunc(a.Adds, func(p FieldSpec) bool { return p.Key == key })
}

// actions are the actions this version defines.
var actions = map[string]CommandAction{
	ActionListDir:      {Params: map[string]FieldType{"path": FieldString}, Result: ResultDirListing},
	ActionDownloadFile: {Params: map[string]FieldType{"path": FieldString}, Result: ResultFileDownload},
	ActionUploadFile: {Params: map[string]FieldType{"path": FieldString, "file": FieldFile, "overwrite": FieldBool},
		Result: ResultFileUpload},
	ActionStreamFile: {Params: map[string]FieldType{"path": FieldString}, Result: ResultFileStream},
	ActionUploadStream: {Params: map[string]FieldType{"path": FieldString, "stream": FieldStream, "overwrite": FieldBool},
		Result: ResultFileUpload},
	ActionDeletePath:       {Params: map[string]FieldType{"path": FieldString, "recursive": FieldBool}},
	ActionWalkDir:          {Params: map[string]FieldType{"path": FieldString}, Result: ResultDirWalk},
	ActionListVolumes:      {Result: ResultVolumes},
	ActionSwitchConnection: {Params: map[string]FieldType{"conn": FieldInt}},
	ActionTunnel: {Adds: tunnelCoreParams(ActionTunnel, []EnumOption{
		{Value: FrontSOCKS, Label: "SOCKS proxy", Description: "SOCKS5 (connect, UDP associate), SOCKS4 and 4a: each tool says where each connection goes."},
		{Value: FrontHTTP, Label: "HTTP proxy", Description: "CONNECT, and plain requests: for the tools that speak no SOCKS."},
		{Value: FrontForward, Label: "Port forward", Description: "Every connection to the port goes to the destination."},
		{Value: FrontTerminal, Label: "Terminal", Description: "A shell, or the program it says, for each connection: in the web app, or raw on the port."},
		{Value: FrontVPN, Label: "VPN", Description: "logos-vpn routes an operator's machine into the minion's networks: every tool there, scans and pings too."}})},
	ActionReverseTunnel: {Params: map[string]FieldType{"bind": FieldString, "listen": FieldInt, "udp": FieldBool},
		Adds: tunnelCoreParams(ActionReverseTunnel, nil)},
}

// KnownResult reports whether this version defines the result.
func KnownResult(id string) bool { return results[id] }

// KnownAction is an action's contract, if this version defines it.
func KnownAction(id string) (CommandAction, bool) {
	a, ok := actions[id]
	return a, ok
}

// validateResultAction checks a command's result and action: each one this
// version defines; the action's params taken, of their types; none of the
// params core adds; every other param with a default, so core can run the
// command with the action's params alone; and the result the action needs.
func validateResultAction(c BuildCommand) error {
	if c.Result != "" && !results[c.Result] {
		return fmt.Errorf("result %q is not one core knows (%s)", c.Result, strings.Join(keysOf(results), ", "))
	}
	if c.Action == "" {
		return nil
	}
	spec, ok := actions[c.Action]
	if !ok {
		return fmt.Errorf("action %q is not one core knows (%s)", c.Action, strings.Join(keysOf(actions), ", "))
	}
	for _, k := range keysOf(spec.Params) {
		i := slices.IndexFunc(c.Params, func(p FieldSpec) bool { return p.Key == k })
		if i < 0 || c.Params[i].Type != spec.Params[k] {
			return fmt.Errorf("action %q takes a %s param %q", c.Action, spec.Params[k], k)
		}
	}
	for _, p := range c.Params {
		if slices.ContainsFunc(spec.Adds, func(a FieldSpec) bool { return a.Key == p.Key }) {
			return fmt.Errorf("param %q is core's: core adds it to every %s command, and a factory declares none", p.Key, c.Action)
		}
		if _, own := spec.Params[p.Key]; !own && p.Default == nil {
			return fmt.Errorf("param %q needs a default: core runs a %s command with the action's params alone", p.Key, c.Action)
		}
	}
	if c.Result != spec.Result {
		if spec.Result == "" {
			return fmt.Errorf("action %q has no result: its commands name none", c.Action)
		}
		return fmt.Errorf("action %q needs result %q", c.Action, spec.Result)
	}
	return nil
}

// keysOf is a map's keys, sorted.
func keysOf[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// DirListing is a dir_listing part's data: Path, Sep and Parent in the
// first part only, Entries in any. A minion encodes it with MarshalCBOR.
type DirListing struct {
	// Path is the directory listed, absolute, as the host writes it.
	Path string `cbor:"path,omitempty" json:"path,omitempty"`
	// Sep is the host's path separator: "/" or "\".
	Sep string `cbor:"sep,omitempty" json:"sep,omitempty"`
	// Parent is the parent directory; empty at a root.
	Parent  string     `cbor:"parent,omitempty" json:"parent,omitempty"`
	Entries []DirEntry `cbor:"entries,omitempty" json:"entries,omitempty"`
	// X holds a factory's own fields.
	X map[string]any `cbor:"x,omitempty" json:"x,omitempty"`
}

// DirEntry is one entry of a directory; "." and ".." are none.
type DirEntry struct {
	// Name is the entry's name in the directory: not empty, no "/".
	Name string `cbor:"name" json:"name"`
	// Type is the entry itself (DirEntryDir, ...), a link not followed.
	Type string `cbor:"type" json:"type"`
	// Size is in bytes, for files (a link: its own size).
	Size *uint64 `cbor:"size,omitempty" json:"size,omitempty"`
	// Modified is unix seconds, negative before 1970.
	Modified *int64 `cbor:"modified,omitempty" json:"modified,omitempty"`
	// Mode is as the host shows it: "-rw-r--r--", or Windows attributes.
	Mode  string `cbor:"mode,omitempty" json:"mode,omitempty"`
	Owner string `cbor:"owner,omitempty" json:"owner,omitempty"`
	Group string `cbor:"group,omitempty" json:"group,omitempty"`
	// Target is a link's target, as the link holds it.
	Target string `cbor:"target,omitempty" json:"target,omitempty"`
	// Hidden is the host's own rule: a dot name, the hidden attribute.
	Hidden bool           `cbor:"hidden,omitempty" json:"hidden,omitempty"`
	X      map[string]any `cbor:"x,omitempty" json:"x,omitempty"`
}

// Entry types. A later version may add types: a reader takes one it does
// not know as DirEntryOther.
const (
	DirEntryDir   = "dir"
	DirEntryFile  = "file"
	DirEntryLink  = "link"
	DirEntryOther = "other"
)

// ReadDirListing decodes a dir_listing part's data and checks it: the
// first part (seq 0) names the directory, later ones only add entries.
// Keys it does not know are ignored.
func ReadDirListing(seq uint64, data cbor.RawMessage) (*DirListing, error) {
	var l DirListing
	if err := cborDec.Unmarshal(data, &l); err != nil {
		return nil, fmt.Errorf("dir_listing: %w", err)
	}
	if seq == 0 {
		switch {
		case l.Path == "":
			return nil, errors.New("dir_listing: the first part names the directory (path)")
		case l.Sep != "/" && l.Sep != `\`:
			return nil, errors.New(`dir_listing: sep is "/" or "\"`)
		}
	} else if l.Path != "" || l.Sep != "" || l.Parent != "" {
		return nil, errors.New("dir_listing: only the first part has path, sep and parent")
	}
	if err := validateEntries(l.Entries); err != nil {
		return nil, fmt.Errorf("dir_listing: %w", err)
	}
	return &l, nil
}

// ResultData encodes v as a result's data: a map, or a struct (a
// DirListing) encoded as one.
func ResultData(v any) (cbor.RawMessage, error) {
	b, err := MarshalCBOR(v)
	if err != nil {
		return nil, err
	}
	if !isCBORMap(b) {
		return nil, errors.New("result data is a map")
	}
	return b, nil
}

// isCBORMap reports whether b starts a CBOR map (major type 5).
func isCBORMap(b []byte) bool {
	return len(b) > 0 && b[0]>>5 == 5
}

// validateEntries checks a directory's entries: each a name and a type.
func validateEntries(entries []DirEntry) error {
	for i, e := range entries {
		switch {
		case e.Name == "" || e.Name == "." || e.Name == "..":
			return fmt.Errorf("entry %d: a name, not %q", i, e.Name)
		case strings.ContainsAny(e.Name, "/\x00"):
			return fmt.Errorf("entry %d: a name without / (%q)", i, e.Name)
		case e.Type == "":
			return fmt.Errorf("entry %d (%q): no type", i, e.Name)
		}
	}
	return nil
}

// ListingPiece is a piece of what a task saw of the host's file system, as
// core keeps it (docs: contracts/minion-messages/tasks-and-results/,
// Listings): a directory's listing, numbered ID within its task, in pieces
// numbered Part from 0, the last with Last. The first piece names the
// directory (Path, Sep, Parent), every piece adds entries. Any command can
// send listings; core keeps them in its file system snapshot as they come,
// outside the task's output and data. It travels as an LsPiece, on a result
// part (ResultItem.Ls), and LsPiece.Named makes one.
type ListingPiece struct {
	ID   uint64
	Part uint64
	Last bool
	// Path is the directory listed, absolute, as the host writes it; Sep
	// the host's separator ("/" or "\"); Parent the directory above it,
	// empty at a root. On part 0 only.
	Path    string
	Sep     string
	Parent  string
	Entries []DirEntry
	// Partial: some entries could not be read; the listing is not the
	// whole directory, so core takes what it has and says nothing of the
	// rest.
	Partial bool
	// Err: the directory could not be read at all (permission denied); on
	// a single last piece, with no entries.
	Err string
}

// Validate checks a piece: the first names its directory, the rest do
// not; an unreadable directory is one piece with no entries.
func (p ListingPiece) Validate() error {
	if p.Part == 0 {
		switch {
		case p.Path == "":
			return errors.New("listing: the first piece names the directory (path)")
		case p.Sep != "/" && p.Sep != `\`:
			return errors.New(`listing: sep is "/" or "\"`)
		}
	} else if p.Path != "" || p.Sep != "" || p.Parent != "" {
		return errors.New("listing: only the first piece has path, sep and parent")
	}
	if p.Err != "" && (p.Part != 0 || !p.Last || len(p.Entries) > 0) {
		return errors.New("listing: an unreadable directory is one last piece, without entries")
	}
	if err := validateEntries(p.Entries); err != nil {
		return fmt.Errorf("listing %d: %w", p.ID, err)
	}
	return nil
}

// DirWalk is a dir_walk part's data: where the walk stands. Each part says
// it whole (the latest part's is the walk's): the directory it began at,
// the folders listed and their entries, those it could not read, those it
// did not enter (deeper than it goes, another file system, past its
// limit), and the folder it is reading, none once it ended.
type DirWalk struct {
	// Root is the directory walked, absolute, as the host writes it.
	Root    string `cbor:"root" json:"root"`
	Folders uint64 `cbor:"folders" json:"folders"`
	Entries uint64 `cbor:"entries" json:"entries"`
	Unread  uint64 `cbor:"unread,omitempty" json:"unread,omitempty"`
	Skipped uint64 `cbor:"skipped,omitempty" json:"skipped,omitempty"`
	Current string `cbor:"current,omitempty" json:"current,omitempty"`
	// X holds a factory's own fields.
	X map[string]any `cbor:"x,omitempty" json:"x,omitempty"`
}

// ReadDirWalk decodes a dir_walk part's data and checks it: every part
// names the directory walked.
func ReadDirWalk(_ uint64, data cbor.RawMessage) (*DirWalk, error) {
	var w DirWalk
	if err := cborDec.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("dir_walk: %w", err)
	}
	if w.Root == "" {
		return nil, errors.New("dir_walk: root names the directory walked")
	}
	return &w, nil
}
