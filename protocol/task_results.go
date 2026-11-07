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
	// ActionSocksProxy runs a tunnel with core's SOCKS proxy in front
	// (tunnels.go): core gives port, the operational port it listens on for
	// the task (0: any free one), which the minion needs nothing of. It has
	// no result: the task runs while the tunnel is open, its streams going
	// as tunnel items, and core shows it. A command may take more, each with
	// a default, which only the minion reads (a connect's timeout, its
	// max_streams).
	ActionSocksProxy = "socks_proxy"
	// ActionPortForward runs a tunnel with a port forward in front: core
	// listens on port as for ActionSocksProxy, and opens each connection to
	// it as a stream to host:to, which core reads and the minion needs
	// nothing of (each stream's tunnel item names it). The same items, the
	// same task, no result; more params, each with a default, the minion's.
	ActionPortForward = "port_forward"
	// ActionReversePortForward runs a tunnel the other way, as ssh -R
	// does: the minion listens on its host at bind:listen (listen 0: any
	// free port) and opens each connection that comes there as a stream,
	// which core connects to host:to from its own network; with udp, it
	// listens for datagrams, a stream for each address they come from,
	// which core sends on to host:to. bind, listen and udp are the
	// minion's, read from its task; host and to are core's alone
	// (CommandAction.CoreParams): they carry no num, so the minion never
	// learns where core sends what comes. The same items, the streams the
	// minion's (tunnels.go); no result; more params, each with a default.
	ActionReversePortForward = "reverse_port_forward"
)

// TunnelActions are the tunnel actions: a task of a command with one
// carries streams as tunnel items, whatever core puts in front of its port
// (SOCKS, a port forward) or the minion listens for (a reverse port
// forward). Such a task holds none of the minion's max_tasks: it runs as
// long as its tunnel is open, a minion's capability rather than its work,
// and both sides count it out. Each may take stop_idle (ParamStopIdle), a
// duration core alone reads: core stops the task once no stream has been
// open for that long (absent or 0: never).
func TunnelActions() []string {
	return []string{ActionSocksProxy, ActionPortForward, ActionReversePortForward}
}

// ParamStopIdle is the tunnel actions' optional, core-only param: a
// duration (FieldDuration) after which, with no stream open, core stops
// the task as Stop does; 0, or a command without it, never.
const ParamStopIdle = "stop_idle"

// IsTunnelAction reports whether action is one of TunnelActions.
func IsTunnelAction(action string) bool { return slices.Contains(TunnelActions(), action) }

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
	// CoreParams are the params that are core's alone: they carry no num,
	// so a task never takes them to the minion (a reverse port forward's
	// destination, a tunnel's stop_idle).
	CoreParams []string
	// Optional are params a command of the action may take or leave out,
	// each of its type: core reads one when the command has it, and does
	// without when it does not (a tunnel's stop_idle). An action gains
	// params only so, so factories built before stay valid.
	Optional map[string]FieldType
}

// IsCoreParam reports whether key is one of action's CoreParams: a param
// with no num, which never goes to the minion.
func IsCoreParam(action, key string) bool {
	a, ok := actions[action]
	return ok && slices.Contains(a.CoreParams, key)
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
	ActionSocksProxy: {Params: map[string]FieldType{"port": FieldInt}, CoreParams: []string{ParamStopIdle},
		Optional: map[string]FieldType{ParamStopIdle: FieldDuration}},
	ActionPortForward: {Params: map[string]FieldType{"port": FieldInt, "host": FieldString, "to": FieldInt},
		CoreParams: []string{ParamStopIdle}, Optional: map[string]FieldType{ParamStopIdle: FieldDuration}},
	ActionReversePortForward: {Params: map[string]FieldType{"bind": FieldString, "listen": FieldInt, "udp": FieldBool, "host": FieldString,
		"to": FieldInt}, CoreParams: []string{"host", "to", ParamStopIdle}, Optional: map[string]FieldType{ParamStopIdle: FieldDuration}},
}

// KnownResult reports whether this version defines the result.
func KnownResult(id string) bool { return results[id] }

// KnownAction is an action's contract, if this version defines it.
func KnownAction(id string) (CommandAction, bool) {
	a, ok := actions[id]
	return a, ok
}

// validateResultAction checks a command's result and action: each one this
// version defines; the action's params taken, of their types; its optional
// ones, when taken, of theirs; every other param with a default, so core
// can run the command with the action's params alone; and the result the
// action needs.
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
	for _, k := range keysOf(spec.Optional) {
		if i := slices.IndexFunc(c.Params, func(p FieldSpec) bool { return p.Key == k }); i >= 0 && c.Params[i].Type != spec.Optional[k] {
			return fmt.Errorf("action %q takes a %s param %q, or none", c.Action, spec.Optional[k], k)
		}
	}
	for _, p := range c.Params {
		_, own := spec.Params[p.Key]
		_, optional := spec.Optional[p.Key]
		if !own && !optional && p.Default == nil {
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
