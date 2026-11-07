package protocol

import (
	"strings"
	"testing"
)

func TestCommandResultsAndActions(t *testing.T) {
	path := FieldSpec{Key: "path", Type: FieldString, Default: "."}
	listDir := func(params ...FieldSpec) BuildCommand {
		return BuildCommand{ID: "ls", Result: ResultDirListing, Action: ActionListDir, Params: params}
	}
	for name, c := range map[string]BuildCommand{
		"neither":                 {ID: "ls"},
		"a result alone":          {ID: "find", Result: ResultDirListing, Params: []FieldSpec{{Key: "name", Type: FieldString, Required: true}}},
		"list_dir":                listDir(path),
		"list_dir, path required": listDir(FieldSpec{Key: "path", Type: FieldString, Required: true}),
		"list_dir, more with defaults": listDir(FieldSpec{Key: "all", Type: FieldBool, Default: false}, path,
			FieldSpec{Key: "depth", Type: FieldInt, Required: true, Default: 1}),
	} {
		if err := validateBuildCommand(c, nil); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, tc := range map[string]struct {
		c    BuildCommand
		want string
	}{
		"unknown result":    {BuildCommand{ID: "ls", Result: "dir_listng"}, `result "dir_listng" is not one core knows (dir_listing, dir_walk, file_download, file_stream, file_upload, volumes)`},
		"unknown action":    {BuildCommand{ID: "ls", Action: "list"}, `action "list" is not one core knows (delete_path, download_file, list_dir, list_volumes, port_forward, reverse_port_forward, socks_proxy, stream_file, switch_connection, upload_file, upload_stream, walk_dir)`},
		"no path":           {listDir(), `action "list_dir" takes a string param "path"`},
		"path not a string": {listDir(FieldSpec{Key: "path", Type: FieldInt}), `takes a string param "path"`},
		"more, no default":  {listDir(path, FieldSpec{Key: "all", Type: FieldBool}), `param "all" needs a default`},
		"more, required, no default": {listDir(FieldSpec{Key: "depth", Type: FieldInt, Required: true}, path),
			`param "depth" needs a default`},
		"action without its result": {BuildCommand{ID: "ls", Action: ActionListDir, Params: []FieldSpec{path}},
			`action "list_dir" needs result "dir_listing"`},
	} {
		err := validateBuildCommand(tc.c, nil)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	upload := BuildCommand{ID: "upload", Result: ResultFileUpload, Action: ActionUploadFile, Params: []FieldSpec{
		{Key: "file", Type: FieldFile, Required: true}, {Key: "path", Type: FieldString, Required: true},
		{Key: "overwrite", Type: FieldBool, Default: false}}}
	if err := validateBuildCommand(upload, nil); err != nil {
		t.Errorf("upload_file: %v", err)
	}
	upload.Params = upload.Params[1:]
	if err := validateBuildCommand(upload, nil); err == nil || !strings.Contains(err.Error(), `takes a file param "file"`) {
		t.Errorf("upload_file without its file: %v", err)
	}
	// An action with no result: the command has none either.
	rm := BuildCommand{ID: "rm", Action: ActionDeletePath, Params: []FieldSpec{
		{Key: "path", Type: FieldString, Required: true}, {Key: "recursive", Type: FieldBool, Default: false}}}
	if err := validateBuildCommand(rm, nil); err != nil {
		t.Errorf("delete_path: %v", err)
	}
	rm.Result = ResultDirListing
	if err := validateBuildCommand(rm, nil); err == nil {
		t.Error("delete_path with a result: taken")
	}
	// switch_connection: conn, no result; BOB's for has a default.
	connect := BuildCommand{ID: "switch", Action: ActionSwitchConnection, Params: []FieldSpec{
		{Key: "conn", Type: FieldInt, Required: true, Min: 1}, {Key: "for", Type: FieldDuration, Default: "0s"}}}
	if err := validateBuildCommand(connect, nil); err != nil {
		t.Errorf("switch_connection: %v", err)
	}
	connect.Params[0].Type = FieldString
	if err := validateBuildCommand(connect, nil); err == nil || !strings.Contains(err.Error(), `takes a int param "conn"`) {
		t.Errorf("switch_connection with a text conn: %v", err)
	}
	if !KnownResult(ResultDirListing) || KnownResult("process_list") {
		t.Error("KnownResult")
	}
	if a, ok := KnownAction(ActionListDir); !ok || a.Result != ResultDirListing || a.Params["path"] != FieldString {
		t.Errorf("KnownAction: %+v %v", a, ok)
	}
}

func TestReadDirListing(t *testing.T) {
	size, mod := uint64(0), int64(-5)
	first := DirListing{Path: `C:\Users\ann`, Sep: `\`, Parent: `C:\Users`, Entries: []DirEntry{
		{Name: "Downloads", Type: DirEntryDir},
		{Name: "empty.txt", Type: DirEntryFile, Size: &size, Modified: &mod, Hidden: true},
	}}
	data, err := ResultData(first)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ReadDirListing(0, data)
	if err != nil {
		t.Fatal(err)
	}
	// An empty file keeps its size, a time before 1970 its sign.
	if got.Path != first.Path || len(got.Entries) != 2 || got.Entries[1].Size == nil || *got.Entries[1].Size != 0 ||
		*got.Entries[1].Modified != -5 || !got.Entries[1].Hidden {
		t.Fatalf("read back %+v", got)
	}

	// Keys it does not know are ignored; a type it does not know passes.
	later, _ := MarshalCBOR(map[string]any{"entries": []any{
		map[string]any{"name": "dev", "type": "socket-ish", "future": 1},
	}, "future": true})
	if _, err := ReadDirListing(3, later); err != nil {
		t.Fatalf("a later part: %v", err)
	}
	// A part with no entries (the done part) is fine.
	empty, _ := ResultData(DirListing{})
	if _, err := ReadDirListing(5, empty); err != nil {
		t.Fatalf("an empty later part: %v", err)
	}

	for name, tc := range map[string]struct {
		seq  uint64
		data any
		want string
	}{
		"no path":           {0, DirListing{Sep: "/"}, "names the directory"},
		"bad sep":           {0, DirListing{Path: "/x", Sep: ":"}, "sep is"},
		"path later":        {1, DirListing{Path: "/x"}, "only the first part"},
		"parent later":      {1, DirListing{Parent: "/"}, "only the first part"},
		"empty name":        {1, DirListing{Entries: []DirEntry{{Type: DirEntryFile}}}, "a name"},
		"dot dot":           {1, DirListing{Entries: []DirEntry{{Name: "..", Type: DirEntryDir}}}, "a name"},
		"slash in name":     {1, DirListing{Entries: []DirEntry{{Name: "a/b", Type: DirEntryFile}}}, "without /"},
		"no type":           {1, DirListing{Entries: []DirEntry{{Name: "a"}}}, "no type"},
		"entries not list":  {1, map[string]any{"entries": "nope"}, "dir_listing"},
		"size not a number": {1, map[string]any{"entries": []any{map[string]any{"name": "a", "type": "file", "size": "4K"}}}, "dir_listing"},
	} {
		raw, err := MarshalCBOR(tc.data)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ReadDirListing(tc.seq, raw)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

func TestListingPiece(t *testing.T) {
	size := uint64(3)
	entries := []DirEntry{{Name: "a.txt", Type: DirEntryFile, Size: &size}, {Name: "docs", Type: DirEntryDir}}
	ok := map[string]ListingPiece{
		"a whole listing in one piece": {ID: 0, Part: 0, Last: true, Path: "/home/u", Sep: "/", Parent: "/home", Entries: entries},
		"a root":                       {ID: 1, Part: 0, Path: `C:\`, Sep: `\`, Entries: entries},
		"a later piece":                {ID: 1, Part: 2, Last: true, Entries: entries},
		"partial":                      {ID: 2, Part: 0, Last: true, Path: "/proc/1", Sep: "/", Partial: true, Entries: entries},
		"unreadable":                   {ID: 3, Part: 0, Last: true, Path: "/root", Sep: "/", Err: "permission denied"},
		"an empty directory":           {ID: 4, Part: 0, Last: true, Path: "/tmp/e", Sep: "/"},
	}
	for name, p := range ok {
		if err := p.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := map[string]ListingPiece{
		"the first without a path":     {Part: 0, Sep: "/"},
		"the first with a bad sep":     {Part: 0, Path: "/x", Sep: ":"},
		"a later piece naming the dir": {Part: 1, Path: "/x"},
		"an err with entries":          {Part: 0, Last: true, Path: "/x", Sep: "/", Err: "denied", Entries: entries},
		"an err not last":              {Part: 0, Path: "/x", Sep: "/", Err: "denied"},
		"an err on a later piece":      {Part: 1, Last: true, Err: "denied"},
		"an entry without a type":      {Part: 0, Path: "/x", Sep: "/", Entries: []DirEntry{{Name: "a"}}},
		"an entry named with a slash":  {Part: 0, Path: "/x", Sep: "/", Entries: []DirEntry{{Name: "a/b", Type: DirEntryFile}}},
		"an entry named ..":            {Part: 0, Path: "/x", Sep: "/", Entries: []DirEntry{{Name: "..", Type: DirEntryDir}}},
	}
	for name, p := range bad {
		if p.Validate() == nil {
			t.Errorf("%s passed", name)
		}
	}
}

func TestResultItemListings(t *testing.T) {
	task := make([]byte, 16)
	r := ResultItem{T: ItemResult, Task: task, Seq: 0, Ls: []LsPiece{{ID: 0, Part: 0, Last: true, Path: "/", Sep: "/"}}}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	// Through CBOR and back, as a minion sends it.
	b, err := cborEnc.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var back ResultItem
	if err := cborDec.Unmarshal(b, &back); err != nil || len(back.Ls) != 1 || back.Ls[0].Path != "/" || !back.Ls[0].Last {
		t.Fatalf("round trip: %+v %v", back, err)
	}
	r.Ls = append(r.Ls, LsPiece{ID: 1, Part: 1, Path: "/x"})
	if r.Validate() == nil {
		t.Fatal("a bad piece passed")
	}
}

func TestDirWalk(t *testing.T) {
	data, err := ResultData(DirWalk{Root: "/home", Folders: 12, Entries: 340, Unread: 1, Current: "/home/u/docs"})
	if err != nil {
		t.Fatal(err)
	}
	w, err := ReadDirWalk(3, data)
	if err != nil || w.Root != "/home" || w.Folders != 12 || w.Current != "/home/u/docs" {
		t.Fatalf("%+v %v", w, err)
	}
	none, _ := ResultData(DirWalk{Folders: 1})
	if _, err := ReadDirWalk(0, none); err == nil {
		t.Fatal("a walk without its root passed")
	}
	if a, ok := KnownAction(ActionWalkDir); !ok || a.Result != ResultDirWalk || a.Params["path"] != FieldString || !KnownResult(ResultDirWalk) {
		t.Fatalf("walk_dir: %+v", a)
	}
}

// A volumes part: its separator, and each volume absolute on the host with
// a kind; list_volumes takes nothing and needs the result.
func TestVolumes(t *testing.T) {
	size, free := uint64(64<<30), uint64(20<<30)
	for _, ok := range []Volumes{
		{Sep: `\`, Volumes: []Volume{{Path: `C:\`, Kind: VolumeFixed, Label: "System", FS: "NTFS", Size: &size, Free: &free},
			{Path: `D:\`, Kind: VolumeOptical, NoMedia: true}, {Path: `Z:\`, Kind: VolumeNetwork, Device: `\\nas\share`}}},
		{Sep: "/", Volumes: []Volume{{Path: "/", Kind: VolumeOther, FS: "overlay"}, {Path: "/boot", Kind: VolumeFixed, Device: "/dev/sda1", ReadOnly: true}}},
		{Sep: "/"},
	} {
		data, err := ResultData(ok)
		if err != nil {
			t.Fatal(err)
		}
		v, err := ReadVolumes(0, data)
		if err != nil || len(v.Volumes) != len(ok.Volumes) {
			t.Fatalf("%+v: %+v %v", ok, v, err)
		}
	}
	for name, bad := range map[string]Volumes{
		"sep":          {Sep: "", Volumes: []Volume{{Path: "/", Kind: VolumeFixed}}},
		"relative":     {Sep: "/", Volumes: []Volume{{Path: "mnt", Kind: VolumeFixed}}},
		"unix on win":  {Sep: `\`, Volumes: []Volume{{Path: "/", Kind: VolumeFixed}}},
		"a bare drive": {Sep: `\`, Volumes: []Volume{{Path: "C:", Kind: VolumeFixed}}},
		"no kind":      {Sep: "/", Volumes: []Volume{{Path: "/"}}},
	} {
		data, _ := ResultData(bad)
		if _, err := ReadVolumes(0, data); err == nil {
			t.Errorf("%s passed", name)
		}
	}
	if a, ok := KnownAction(ActionListVolumes); !ok || a.Result != ResultVolumes || len(a.Params) != 0 || !KnownResult(ResultVolumes) {
		t.Fatalf("list_volumes: %+v", a)
	}
	// A command of it takes no param core must give; its own have defaults.
	c := BuildCommand{ID: "volumes", Action: ActionListVolumes, Result: ResultVolumes}
	if err := validateResultAction(c); err != nil {
		t.Fatal(err)
	}
	c.Result = ResultDirListing
	if err := validateResultAction(c); err == nil || !strings.Contains(err.Error(), `needs result "volumes"`) {
		t.Fatalf("a list_volumes command without its result: %v", err)
	}
}
