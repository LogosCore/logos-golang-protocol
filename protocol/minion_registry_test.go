package protocol

import (
	"bytes"
	"maps"
	"net"
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
	entry := LsEntry{Name: "a", Type: EntryFile, Size: &size, Modified: &mod, Mode: 0o100644, Owner: 1, Group: 1,
		Target: "t", Hidden: true, X: map[string]any{"k": "v"}}
	item := 0
	for _, c := range []struct {
		v    any
		t    int
		keys []uint64
	}{
		{MinionMessage{V: MinionMessageV3, ID: id, Re: id, Items: []cbor.RawMessage{{0xa0}}}, -1, []uint64{0, 1, 2, 3}},
		{CoreMessage{V: MinionMessageV3, ID: id, Re: id, Items: []cbor.RawMessage{{0xa0}}, At: 1}, -1, []uint64{0, 1, 2, 3, 4}},
		{StageItem{T: ItemStage, Key: id, Corr: id}, 1, []uint64{0, 1, 2}},
		{StageResponseItem{T: ItemStageResponse, TID: id, Keys: id, Corr: id}, 2, []uint64{0, 1, 2, 3}},
		{HelloItem{T: ItemHello, PID: 1, OS: "o", Arch: "a", Host: "h", User: "u", Domain: "d", Proc: "p",
			Integrity: IntegrityHigh, Addrs: []net.IP{{10, 0, 0, 1}}, Version: "v", MachineSource: MachineKept,
			MachineValue: "m", X: map[string]any{"k": 1}, SID: id, Sleep: &Sleep{1, 2}, Conn: 2}, 3,
			[]uint64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}},
		{Sleep{1, 2}, -1, []uint64{1, 2}},
		{HelloResponseItem{T: ItemHelloResponse, SID: id}, 4, []uint64{0, 1}},
		{SleepUpdateItem{T: ItemSleepUpdate, Interval: 1, Jitter: 2}, 5, []uint64{0, 1, 2}},
		{GetTasksItem{T: ItemGetTasks, Max: &one}, 7, []uint64{0, 1}},
		{TaskItem{T: ItemTask, Task: id, Cmd: 3, Args: Args{1: 1}}, 8, []uint64{0, 1, 2, 3}},
		{CancelItem{T: ItemCancel, Task: id, Ctx: id}, 9, []uint64{0, 1, 2}},
		{ResultItem{T: ItemResult, Task: id, Seq: 1, Done: true, OK: &yes, Out: id, Err: "e", Data: []byte{0xa0},
			Exit: &code, Ls: []LsPiece{{Path: "/"}}, Ctx: id}, 10, []uint64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}},
		{AckItem{T: ItemAck, Tasks: [][]byte{id}, Xfer: id, Next: &one, Hold: true, Ctx: id}, 11, []uint64{0, 1, 2, 3, 4, 5}},
		{ChunkItem{T: ItemChunk, Xfer: id, Off: 0, Data: id, Total: &one, SHA256: id, Task: id, Name: "n", Ctx: id}, 12,
			[]uint64{0, 1, 2, 3, 4, 5, 6, 7, 8}},
		{ErrItem{T: ItemErr, Code: ErrItemBadMessage, Msg: "m", Item: &item, Task: id, Ctx: id}, 13, []uint64{0, 1, 2, 3, 4, 5}},
		{ConnUpdateItem{T: ItemConnUpdate, Conn: 2, Reason: "r"}, 14, []uint64{0, 1, 2}},
		{RehelloItem{T: ItemRehello}, 6, []uint64{0}},
		{ResumeItem{T: ItemResume, Task: id, Ctx: id}, 15, []uint64{0, 1, 2}},
		{PollItem{T: ItemPoll, Within: 1000}, 16, []uint64{0, 1}},
		{ReackItem{T: ItemReack, Tasks: [][]byte{id}}, 19, []uint64{0, 1}},
		{IdentityItem{T: ItemIdentity, Scope: IdentityTask, Task: id, User: "u", Domain: "d", Integrity: IntegrityRoot,
			How: IdentityBecome, Credential: "c"}, 20, []uint64{0, 1, 2, 3, 4, 5, 6, 7}},
		{LinkActing{Task: id, Cmd: 1, Args: Args{1: 1}}, -1, []uint64{1, 2, 3}},
		{FileOffer{Xfer: id, Name: "n", Size: 1, SHA256: id, Stream: true}, -1, []uint64{1, 2, 3, 4, 5}},
		{LsPiece{ID: 1, Part: 1, Last: true, Path: "/", Sep: "/", Parent: "/", Entries: []LsEntry{entry},
			Partial: true, Err: ListingErrOther, Owners: []string{"root"}, ErrMsg: "m"}, -1,
			[]uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}},
		{entry, -1, []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}},
		{AES256CBCHMACSHA256Material{EncKey: id, MACKey: id}, -1, []uint64{1, 2}},
		{fileDownloadWire{Xfer: id, Path: "p", Size: 1, SHA256: id, X: map[string]any{"k": 1}}, -1, []uint64{1, 2, 3, 4, 5}},
		{fileUploadWire{Xfer: id, Path: "p", Size: 1, SHA256: id, X: map[string]any{"k": 1}}, -1, []uint64{1, 2, 3, 4, 5}},
		{fileStreamWire{Xfer: id, Path: "p", Size: 1, SHA256: id, X: map[string]any{"k": 1}}, -1, []uint64{1, 2, 3, 4, 5}},
		{dirWalkWire{Root: "/", Folders: 1, Entries: 1, Unread: 1, Skipped: 1, Current: "/a", X: map[string]any{"k": 1}}, -1,
			[]uint64{1, 2, 3, 4, 5, 6, 7}},
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
	for name, got := range map[string][]int{
		"err codes":       {ErrItemBadMessage, ErrItemUnknownItem, ErrItemUnknownTask, ErrItemTooLarge, ErrItemSessionClosed, ErrItemSessionReplaced, ErrItemStale},
		"integrity":       {IntegrityLow, IntegrityMedium, IntegrityHigh, IntegritySystem, IntegrityRoot, IntegrityUser},
		"identity scopes": {IdentitySession, IdentityTask},
		"identity ways":   {IdentityImpersonation, IdentityNetwork, IdentityBecome},
		"entry types":     {EntryDir, EntryFile, EntryLink, EntryOther},
		"listing errors":  {ListingErrDenied, ListingErrNotFound, ListingErrOther},
		"machine sources": {MachineSMBIOSUUID, MachineMacUUID, MachineBSDHostUUID, MachineLinuxMachineID, MachineWinMachineGUID, MachineContainer, MachineDomainSID, MachineHostname, MachineKept, MachineEphemeral, MachineSSHHostKey},
	} {
		for i, n := range got {
			if n != i+1 {
				t.Errorf("%s: %v, want 1, 2, 3…", name, got)
				break
			}
		}
	}
	for got, want := range map[string]string{
		ItemName(ItemGetTasks): "get_tasks", ItemName(6): "rehello", ItemName(99): "item 99",
		ErrCodeName(ErrItemSessionClosed): "session_closed", ErrCodeName(0): "code 0",
		ItemName(ItemPoll): "poll", ErrCodeName(ErrItemStale): "stale",
		IntegrityName(IntegritySystem): "system", IntegrityName(0): "", IntegrityName(9): "level 9",
		MachineSourceName(MachineWinMachineGUID): "win-machine-guid", MachineSourceName(42): "source-42",
		MachineSourceName(MachineSSHHostKey): "ssh-host-key", LinkFailName(LinkFailLogin): "login",
		LinkFailName(LinkFailHostKey): "host_key",
		EntryTypeName(EntryLink):      "link", EntryTypeName(9): "other",
	} {
		if got != want {
			t.Errorf("name %q, want %q", got, want)
		}
	}
}

// A listing piece travels numbered, its owners once, and core reads it back
// named, its mode as the host shows it; a dir_listing's data keeps names.
func TestLsPiece(t *testing.T) {
	size := uint64(3)
	p := LsPiece{ID: 2, Part: 0, Last: true, Path: "/etc", Sep: "/", Parent: "/"}
	for _, name := range []string{"hosts", "shadow", "ssh"} {
		e := LsEntry{Name: name, Type: EntryFile, Size: &size, Mode: 0o100644, Owner: p.Owner("root"), Group: p.Owner("root")}
		if name == "ssh" {
			e.Type, e.Mode, e.Group = EntryDir, 0o40755, p.Owner("wheel")
		}
		p.Entries = append(p.Entries, e)
	}
	if !slices.Equal(p.Owners, []string{"root", "wheel"}) {
		t.Fatalf("owners %v", p.Owners)
	}
	b, err := MarshalCBOR(ResultItem{T: ItemResult, Task: bytes.Repeat([]byte{1}, 16), Seq: 0, Ls: []LsPiece{p}})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("dir")) || bytes.Contains(b, []byte("rw")) || bytes.Count(b, []byte("root")) != 1 {
		t.Fatalf("names or rendered modes on the wire: %x", b)
	}
	var back ResultItem
	if err := UnmarshalCBOR(b, &back); err != nil || len(back.Ls) != 1 || back.Validate() != nil {
		t.Fatalf("%+v %v", back, err)
	}
	got := back.Ls[0].Named("linux")
	e := got.Entries[0]
	if got.Validate() != nil || len(got.Entries) != 3 || e.Name != "hosts" || e.Type != DirEntryFile || *e.Size != 3 ||
		e.Mode != "-rw-r--r--" || e.Owner != "root" || e.Group != "root" ||
		got.Entries[2].Type != DirEntryDir || got.Entries[2].Mode != "drwxr-xr-x" || got.Entries[2].Group != "wheel" {
		t.Fatalf("named: %+v", got.Entries)
	}
	data, err := ResultData(DirListing{Path: "/etc", Sep: "/", Entries: got.Entries})
	if err != nil || !bytes.Contains(data, []byte("entries")) || !bytes.Contains(data, []byte("-rw-r--r--")) {
		t.Fatalf("dir_listing data: %x %v", data, err)
	}
	for name, bad := range map[string]LsPiece{
		"no type":       {Path: "/", Sep: "/", Entries: []LsEntry{{Name: "a"}}},
		"owner missing": {Path: "/", Sep: "/", Entries: []LsEntry{{Name: "a", Type: EntryFile, Owner: 1}}},
		"msg alone":     {Path: "/", Sep: "/", Last: true, ErrMsg: "x"},
		"err, entries":  {Path: "/", Sep: "/", Last: true, Err: ListingErrDenied, Entries: []LsEntry{{Name: "a", Type: EntryFile}}},
	} {
		if bad.Validate() == nil {
			t.Errorf("%s: valid", name)
		}
	}
	for code, want := range map[[2]string]string{
		{"1", ""}: "permission denied", {"2", "gone"}: "not found: gone", {"3", "EIO"}: "EIO", {"3", ""}: "could not be read",
	} {
		n := int(code[0][0] - '0')
		if got := (LsPiece{Path: "/", Sep: "/", Last: true, Err: n, ErrMsg: code[1]}).Named("linux").Err; got != want {
			t.Errorf("err %v: %q, want %q", code, got, want)
		}
	}
}

func TestRenderMode(t *testing.T) {
	for _, c := range []struct {
		os   string
		mode uint32
		want string
	}{
		{"linux", 0o100644, "-rw-r--r--"},
		{"linux", 0o40755, "drwxr-xr-x"},
		{"linux", 0o120777, "lrwxrwxrwx"},
		{"linux", 0o104755, "-rwsr-xr-x"},
		{"linux", 0o102644, "-rw-r-Sr--"},
		{"linux", 0o41777, "drwxrwxrwt"},
		{"darwin", 0o20620, "crw--w----"},
		{"linux", 0o10600, "prw-------"},
		{"linux", 0o140755, "srwxr-xr-x"},
		{"linux", 0, ""},
		{"windows", 0x10, "d-----"},
		{"windows", 0x20 | 0x1 | 0x2, "-arh--"},
		{"windows", 0x10 | 0x400 | 0x4, "d---sl"},
	} {
		if got := RenderMode(c.os, c.mode); got != c.want {
			t.Errorf("%s %o: %q, want %q", c.os, c.mode, got, c.want)
		}
	}
}

// The data of the results this package defines travels numbered and comes
// back named; a factory's own shape passes as it is.
func TestResultDataWire(t *testing.T) {
	xfer, sum := bytes.Repeat([]byte{2}, 16), bytes.Repeat([]byte{3}, 32)
	for result, v := range map[string]any{
		ResultFileDownload: FileDownload{Xfer: xfer, Path: "/etc/hosts", Size: 9, SHA256: sum, X: map[string]any{"k": "v"}},
		ResultFileUpload:   &FileUpload{Xfer: xfer, Path: "/tmp/a", Size: 9, SHA256: sum},
		ResultFileStream:   FileStream{Xfer: xfer, Path: "/big", Size: 1 << 40},
		ResultDirWalk:      DirWalk{Root: "/", Folders: 3, Entries: 40, Unread: 1, Current: "/usr"},
		ResultVolumes: Volumes{Sep: "/", Volumes: []Volume{{Path: "/boot", Kind: VolumeFixed, Device: "/dev/sda1", Size: &[]uint64{1 << 30}[0],
			X: map[string]any{"uuid": "e4"}}}},
	} {
		wire, err := WireResultData(v)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(wire, []byte("path")) || bytes.Contains(wire, []byte("root")) || bytes.Contains(wire, []byte("xfer")) ||
			bytes.Contains(wire, []byte("kind")) {
			t.Errorf("%s: names on the wire: %x", result, wire)
		}
		named, err := NamedResultData(result, wire)
		if err != nil {
			t.Fatalf("%s: %v", result, err)
		}
		switch result {
		case ResultFileDownload:
			if f, err := ReadFileDownload(0, named); err != nil || f.Path != "/etc/hosts" || f.X["k"] != "v" {
				t.Errorf("download: %+v %v", f, err)
			}
		case ResultFileUpload:
			if f, err := ReadFileUpload(0, named); err != nil || f.Path != "/tmp/a" {
				t.Errorf("upload: %+v %v", f, err)
			}
		case ResultFileStream:
			if f, err := ReadFileStream(0, named); err != nil || f.Size != 1<<40 {
				t.Errorf("stream: %+v %v", f, err)
			}
		case ResultDirWalk:
			if w, err := ReadDirWalk(0, named); err != nil || w.Folders != 3 || w.Current != "/usr" {
				t.Errorf("walk: %+v %v", w, err)
			}
		case ResultVolumes:
			if v, err := ReadVolumes(0, named); err != nil || len(v.Volumes) != 1 || v.Volumes[0].Device != "/dev/sda1" ||
				*v.Volumes[0].Size != 1<<30 || v.Volumes[0].X["uuid"] != "e4" {
				t.Errorf("volumes: %+v %v", v, err)
			}
		}
	}
	own, _ := WireResultData(map[string]any{"pids": []int{1, 2}})
	if back, err := NamedResultData("", own); err != nil || !bytes.Equal(back, own) {
		t.Fatalf("a factory's shape: %x %v", back, err)
	}
	if _, err := NamedResultData(ResultDirWalk, []byte{0x01}); err == nil {
		t.Fatal("a walk's data that is not a map passed")
	}
}

// Args travel by number; a file offer stays the CBOR it came as; WireArgs
// numbers a task's args by its params.
func TestArgsWire(t *testing.T) {
	offer := FileOffer{Xfer: bytes.Repeat([]byte{1}, 16), Name: "a.exe", Size: 1, SHA256: make([]byte, 32)}
	params := []FieldSpec{{Key: "path", Num: 1}, {Key: "file", Num: 2}, {Key: "env", Num: 3}, {Key: "none", Num: 4}, {Key: "unnumbered"}}
	args := WireArgs(params, map[string]any{"file": offer, "path": "/tmp", "env": map[string]any{"A": "1"},
		"none": map[string]any{}, "unnumbered": 1, "unknown": 2})
	if len(args) != 4 {
		t.Fatalf("wire args %v", args)
	}
	b, err := MarshalCBOR(TaskItem{T: ItemTask, Task: offer.Xfer, Cmd: 7, Args: args})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("path")) || bytes.Contains(b, []byte("file")) {
		t.Fatalf("param keys on the wire: %x", b)
	}
	var task TaskItem
	if err := UnmarshalCBOR(b, &task); err != nil {
		t.Fatal(err)
	}
	if _, ok := task.Args[3].(map[string]any); !ok || task.Args[1] != "/tmp" {
		t.Fatalf("args: %#v", task.Args)
	}
	if _, ok := task.Args[4].(map[string]any); !ok {
		t.Fatalf("an empty map: %#v", task.Args[4])
	}
	if s, ok := ArgString(task.Args, 1); !ok || s != "/tmp" {
		t.Fatal("ArgString by number")
	}
	got, err := ArgFile(task.Args, 2)
	if err != nil || got.Name != "a.exe" {
		t.Fatalf("ArgFile: %+v %v", got, err)
	}
	if _, err := MarshalCBOR(task); err != nil {
		t.Fatalf("sent again: %v", err)
	}
}

// A poll says a wait of a day at most; an err echoes a ctx of the transfer
// limit at most; ItemCtx reads the ctx of the items that carry one.
func TestPollErrCtx(t *testing.T) {
	if (PollItem{T: ItemPoll, Within: 1000}).Validate() != nil || (PollItem{T: ItemPoll, Within: MaxPollWithin + 1}).Validate() == nil {
		t.Fatal("poll's within")
	}
	id := bytes.Repeat([]byte{1}, 16)
	if (ErrItem{T: ItemErr, Code: 1, Task: id, Ctx: []byte("x")}).Validate() != nil {
		t.Fatal("a valid err")
	}
	for name, bad := range map[string]ErrItem{
		"short task": {T: ItemErr, Code: 3, Task: id[:3]},
		"long ctx":   {T: ItemErr, Code: 1, Ctx: make([]byte, MaxTransferCtx+1)},
	} {
		if bad.Validate() == nil {
			t.Errorf("%s: valid", name)
		}
	}
	next := uint64(4)
	for _, c := range []struct {
		v    any
		want string
	}{
		{ChunkItem{T: ItemChunk, Xfer: id, Data: []byte("d"), Ctx: []byte("chunk")}, "chunk"},
		{AckItem{T: ItemAck, Xfer: id, Next: &next, Ctx: []byte("ack")}, "ack"},
		{ResultItem{T: ItemResult, Task: id, Ctx: []byte("walk")}, "walk"},
		{AckItem{T: ItemAck, Xfer: id, Next: &next}, ""},
		{GetTasksItem{T: ItemGetTasks}, ""},
	} {
		b, err := MarshalCBOR(c.v)
		if err != nil {
			t.Fatal(err)
		}
		if got := string(ItemCtx(b)); got != c.want {
			t.Errorf("%T: ctx %q, want %q", c.v, got, c.want)
		}
	}
}
