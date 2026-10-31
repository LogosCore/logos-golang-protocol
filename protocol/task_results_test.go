package protocol

import (
	"strings"
	"testing"
)

func TestCommandHandlers(t *testing.T) {
	path := FieldSpec{Key: "path", Type: FieldString, Default: "."}
	for name, c := range map[string]BuildCommand{
		"none":              {ID: "ls"},
		"dir_listing":       {ID: "ls", Handler: HandlerDirListing, Params: []FieldSpec{path}},
		"dir_listing, more": {ID: "ls", Handler: HandlerDirListing, Params: []FieldSpec{{Key: "all", Type: FieldBool, Default: false}, path}},
		"dir_listing, more, required with a default": {ID: "ls", Handler: HandlerDirListing,
			Params: []FieldSpec{path, {Key: "depth", Type: FieldInt, Required: true, Default: 1}}},
		"path required":       {ID: "ls", Handler: HandlerDirListing, Params: []FieldSpec{{Key: "path", Type: FieldString, Required: true}}},
		"one this lacks":      {ID: "ps", Handler: "process_list"},
		"one this lacks, too": {ID: "ps", Handler: "future_thing_v2", Params: []FieldSpec{path}},
	} {
		if err := validateBuildCommand(c, nil); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, tc := range map[string]struct {
		c    BuildCommand
		want string
	}{
		"bad id":            {BuildCommand{ID: "ls", Handler: "Dir-Listing"}, "handler must match"},
		"no path":           {BuildCommand{ID: "ls", Handler: HandlerDirListing}, `takes a string param "path"`},
		"path not a string": {BuildCommand{ID: "ls", Handler: HandlerDirListing, Params: []FieldSpec{{Key: "path", Type: FieldInt}}}, `takes a string param "path"`},
		"more, optional without a default": {BuildCommand{ID: "ls", Handler: HandlerDirListing,
			Params: []FieldSpec{path, {Key: "all", Type: FieldBool}}}, `param "all" needs a default`},
		"more, required without a default": {BuildCommand{ID: "ls", Handler: HandlerDirListing,
			Params: []FieldSpec{{Key: "depth", Type: FieldInt, Required: true}, path}}, `param "depth" needs a default`},
	} {
		err := validateBuildCommand(tc.c, nil)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	if !KnownHandler(HandlerDirListing) || KnownHandler("process_list") {
		t.Error("KnownHandler")
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
