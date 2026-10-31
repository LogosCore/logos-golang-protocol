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
		"unknown result":    {BuildCommand{ID: "ls", Result: "dir_listng"}, `result "dir_listng" is not one core knows (dir_listing, file_download)`},
		"unknown action":    {BuildCommand{ID: "ls", Action: "list"}, `action "list" is not one core knows (download_file, list_dir)`},
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
