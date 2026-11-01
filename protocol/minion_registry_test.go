package protocol

import (
	"bytes"
	"maps"
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// keysOfCBOR are the integer keys of a CBOR map, sorted.
func keysOfCBOR(t *testing.T, b []byte) []uint64 {
	t.Helper()
	var m map[uint64]cbor.RawMessage
	if err := cborDec.Unmarshal(b, &m); err != nil {
		t.Fatalf("not an integer-keyed map: %v (%x)", err, b)
	}
	return slices.Sorted(maps.Keys(m))
}

// The registry: every protocol map's keys are the numbers the docs give
// (Wire format, Registry), and an item's type is its key 0. A test fails
// when a number moves.
func TestRegistry(t *testing.T) {
	id, one, yes, code := bytes.Repeat([]byte{1}, 16), uint64(1), true, int64(0)
	size, mod := uint64(5), int64(1)
	entry := DirEntry{Name: "a", Type: DirEntryFile, Size: &size, Modified: &mod, Mode: "-rw-", Owner: "o", Group: "g",
		Target: "t", Hidden: true, X: map[string]any{"k": "v"}}
	item := 0
	for _, c := range []struct {
		v    any
		t    int
		keys []uint64
	}{
		{MinionMessage{V: MinionMessageV2, ID: id, Re: id, Items: []cbor.RawMessage{{0xa0}}}, -1, []uint64{0, 1, 2, 3}},
		{CoreMessage{V: MinionMessageV2, ID: id, Re: id, Items: []cbor.RawMessage{{0xa0}}}, -1, []uint64{0, 1, 2, 3}},
		{StageItem{T: ItemStage, Key: id, Corr: id}, 1, []uint64{0, 1, 2}},
		{StageResponseItem{T: ItemStageResponse, TID: id, Keys: id, Corr: id}, 2, []uint64{0, 1, 2, 3}},
		{HelloItem{T: ItemHello, PID: 1, OS: "o", Arch: "a", Host: "h", User: "u", Domain: "d", Proc: "p",
			Integrity: "high", Addrs: []string{"a"}, Version: "v", MachineID: "m", X: map[string]any{"k": 1}, SID: id,
			Sleep: &Sleep{1, 2}}, 3, []uint64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}},
		{Sleep{1, 2}, -1, []uint64{1, 2}},
		{HelloResponseItem{T: ItemHelloResponse, SID: id}, 4, []uint64{0, 1}},
		{SleepUpdateItem{T: ItemSleepUpdate, Interval: 1, Jitter: 2}, 5, []uint64{0, 1, 2}},
		{GetTasksItem{T: ItemGetTasks, Max: &one}, 7, []uint64{0, 1}},
		{TaskItem{T: ItemTask, Task: id, Cmd: "c", Args: Args{"a": 1}}, 8, []uint64{0, 1, 2, 3}},
		{CancelItem{T: ItemCancel, Task: id}, 9, []uint64{0, 1}},
		{ResultItem{T: ItemResult, Task: id, Seq: 1, Done: true, OK: &yes, Out: id, Err: "e", Data: []byte{0xa0},
			Exit: &code, Ls: []ListingPiece{{Path: "/"}}}, 10, []uint64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}},
		{AckItem{T: ItemAck, Tasks: [][]byte{id}, Xfer: id, Next: &one, Hold: true}, 11, []uint64{0, 1, 2, 3, 4}},
		{ChunkItem{T: ItemChunk, Xfer: id, Off: 0, Data: id, Total: &one, SHA256: id, Task: id, Name: "n"}, 12,
			[]uint64{0, 1, 2, 3, 4, 5, 6, 7}},
		{ErrItem{T: ItemErr, Code: ErrItemBadMessage, Msg: "m", Item: &item}, 13, []uint64{0, 1, 2, 3}},
		{FileOffer{Xfer: id, Name: "n", Size: 1, SHA256: id, Stream: true}, -1, []uint64{1, 2, 3, 4, 5}},
		{ListingPiece{ID: 1, Part: 1, Last: true, Path: "/", Sep: "/", Parent: "/", Entries: []DirEntry{entry},
			Partial: true, Err: "e"}, -1, []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9}},
		{listingEntry(entry), -1, []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}},
		{AES256CBCHMACSHA256Material{EncKey: id, MACKey: id}, -1, []uint64{1, 2}},
	} {
		b, err := MarshalCBOR(c.v)
		if err != nil {
			t.Fatal(err)
		}
		if got := keysOfCBOR(t, b); !slices.Equal(got, c.keys) {
			t.Errorf("%T: keys %v, want %v", c.v, got, c.keys)
		}
		if c.t >= 0 && ItemType(b) != c.t {
			t.Errorf("%T: type %d, want %d", c.v, ItemType(b), c.t)
		}
	}
	codes := []int{ErrItemBadMessage, ErrItemUnknownItem, ErrItemUnknownTask, ErrItemTooLarge, ErrItemSessionClosed,
		ErrItemSessionReplaced}
	if !slices.Equal(codes, []int{1, 2, 3, 4, 5, 6}) {
		t.Errorf("err codes %v", codes)
	}
	if ItemName(ItemGetTasks) != "get_tasks" || ItemName(6) != "rehello" || ItemName(99) != "item 99" ||
		ErrCodeName(ErrItemSessionClosed) != "session_closed" || ErrCodeName(0) != "code 0" {
		t.Error("names")
	}
}

// A listing piece's entries travel with integer keys and come back whole;
// a dir_listing's data keeps text keys.
func TestListingPieceWire(t *testing.T) {
	size := uint64(3)
	p := ListingPiece{ID: 2, Part: 0, Last: true, Path: "/etc", Sep: "/", Parent: "/",
		Entries: []DirEntry{{Name: "hosts", Type: DirEntryFile, Size: &size, X: map[string]any{"inode": uint64(7)}}}}
	b, err := MarshalCBOR(ResultItem{T: ItemResult, Task: bytes.Repeat([]byte{1}, 16), Seq: 0, Ls: []ListingPiece{p}})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("name")) || bytes.Contains(b, []byte("entries")) {
		t.Fatalf("text keys on the wire: %x", b)
	}
	var back ResultItem
	if err := UnmarshalCBOR(b, &back); err != nil || len(back.Ls) != 1 {
		t.Fatalf("%+v %v", back, err)
	}
	got := back.Ls[0]
	if got.Path != "/etc" || !got.Last || len(got.Entries) != 1 || got.Entries[0].Name != "hosts" ||
		*got.Entries[0].Size != 3 || got.Entries[0].X["inode"] != uint64(7) || got.Validate() != nil {
		t.Fatalf("back: %+v", got)
	}
	data, err := ResultData(DirListing{Path: "/etc", Sep: "/", Entries: p.Entries})
	if err != nil || !bytes.Contains(data, []byte("entries")) || !bytes.Contains(data, []byte("name")) {
		t.Fatalf("dir_listing data: %x %v", data, err)
	}
}

// Args keep a file offer as the CBOR it came as, and every other value
// decoded; core can send them again as they are.
func TestArgsWire(t *testing.T) {
	offer := FileOffer{Xfer: bytes.Repeat([]byte{1}, 16), Name: "a.exe", Size: 1, SHA256: make([]byte, 32)}
	b, err := MarshalCBOR(TaskItem{T: ItemTask, Task: offer.Xfer, Cmd: "upload", Args: Args{
		"file": offer, "path": "/tmp", "env": map[string]any{"A": "1"}, "none": map[string]any{}}})
	if err != nil {
		t.Fatal(err)
	}
	var task TaskItem
	if err := UnmarshalCBOR(b, &task); err != nil {
		t.Fatal(err)
	}
	if _, ok := task.Args["env"].(map[string]any); !ok || task.Args["path"] != "/tmp" {
		t.Fatalf("args: %#v", task.Args)
	}
	if _, ok := task.Args["none"].(map[string]any); !ok {
		t.Fatalf("an empty map: %#v", task.Args["none"])
	}
	got, err := ArgFile(task.Args, "file")
	if err != nil || got.Name != "a.exe" {
		t.Fatalf("ArgFile: %+v %v", got, err)
	}
	again, err := MarshalCBOR(task)
	if err != nil || !bytes.Equal(again, b) && len(again) != len(b) {
		t.Fatalf("sent again: %x %v", again, err)
	}
	if ItemType(b) != ItemTask {
		t.Fatal("type")
	}
}
