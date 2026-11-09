package protocol

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func five() *uint64 { n := uint64(5); return &n }

// The check-in of the Codecs page's JSON envelope section, verbatim.
func TestJSONEnvelopeDocExample(t *testing.T) {
	id := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	msg := mustCBOR(t, MinionMessage{V: MinionMessageV3, ID: id, Items: []cbor.RawMessage{
		mustCBOR(t, GetTasksItem{T: ItemGetTasks, Max: five()}),
	}})
	js, err := JSONEnvelope.WriteMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"0":3,"1":"AAECAwQFBgcICQoLDA0ODw==","3":[{"0":7,"1":5}]}`
	if string(js) != want {
		t.Fatalf("got %s\nwant %s", js, want)
	}
	if len(msg) != 28 || len(js) != 58 {
		t.Fatalf("sizes %d and %d, the page says 28 and 58", len(msg), len(js))
	}
	back, err := JSONEnvelope.ReadMessage([]byte(want))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, msg) {
		t.Fatalf("read back %x, want %x", back, msg)
	}
	// A reader takes whitespace.
	spaced := "\n{ \"0\" : 3,\t\"1\": \"AAECAwQFBgcICQoLDA0ODw==\", \"3\": [ {\"0\": 7, \"1\": 5} ] }\r\n"
	if back, err := JSONEnvelope.ReadMessage([]byte(spaced)); err != nil || !bytes.Equal(back, msg) {
		t.Fatalf("with whitespace: %x, %v", back, err)
	}
}

// roundTrip writes a message of items as JSON, reads it back, and checks
// every item decodes to what it was.
func roundTrip(t *testing.T, items ...any) string {
	t.Helper()
	raws := make([]cbor.RawMessage, len(items))
	for i, it := range items {
		raws[i] = mustCBOR(t, it)
	}
	msg := mustCBOR(t, CoreMessage{V: MinionMessageV3, ID: NewMessageID(), Items: raws, At: 1_762_700_000})
	js, err := JSONEnvelope.WriteMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	back, err := JSONEnvelope.ReadMessage(js)
	if err != nil {
		t.Fatalf("%v\n%s", err, js)
	}
	var m CoreMessage
	if err := UnmarshalCBOR(back, &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Items) != len(items) || m.At != 1_762_700_000 {
		t.Fatalf("read back %+v", m)
	}
	for i, it := range items {
		got := reflect.New(reflect.TypeOf(it))
		if err := UnmarshalCBOR(m.Items[i], got.Interface()); err != nil {
			t.Fatalf("item %d: %v", i, err)
		}
		if g := got.Elem().Interface(); !reflect.DeepEqual(g, it) && !sameCBOR(t, g, it) {
			t.Fatalf("item %d:\n got %#v\nwant %#v\njson %s", i, g, it, js)
		}
	}
	return string(js)
}

// sameCBOR says whether two items are the same CBOR values, a map's keys in
// any order: MarshalCBOR writes them in Go's map order, which is random, and
// a RawMessage keeps the order it was written in, so a result's data read
// back from JSON can differ byte for byte from the one written.
func sameCBOR(t *testing.T, a, b any) bool {
	t.Helper()
	// The library's own decoder: UnmarshalCBOR reads open maps with text
	// keys alone, and a result's data has numbered ones.
	var x, y any
	if err := cbor.Unmarshal(mustCBOR(t, a), &x); err != nil {
		t.Fatal(err)
	}
	if err := cbor.Unmarshal(mustCBOR(t, b), &y); err != nil {
		t.Fatal(err)
	}
	return reflect.DeepEqual(x, y)
}

func TestJSONEnvelopeItemsRoundTrip(t *testing.T) {
	task := bytes.Repeat([]byte{7}, 16)
	ok, exit, one := true, int64(0), 1
	size := uint64(4096)
	offer := mustCBOR(t, FileOffer{Xfer: bytes.Repeat([]byte{9}, 16), Name: "a.txt", Size: 5, SHA256: bytes.Repeat([]byte{1}, 32)})
	js := roundTrip(t,
		StageItem{T: ItemStage, Key: []byte("der"), Corr: []byte{1, 2}},
		HelloItem{T: ItemHello, PID: 42, OS: "linux", Arch: "amd64", Host: "box", User: `dom\u "q"`,
			X: map[string]any{"note": "ünï\n", "blob": []byte{0xff, 0}, "n": uint64(3), "neg": int64(-2), "f": 2.0,
				"list": []any{"a", uint64(1), true, nil}}},
		TaskItem{T: ItemTask, Task: task, Cmd: 3, Args: Args{1: "ls -la", 2: uint64(30), 3: true, 4: offer}},
		ResultItem{T: ItemResult, Task: task, Seq: 2, Done: true, OK: &ok, Out: []byte("hello\x00"), Exit: &exit,
			Data: mustCBOR(t, map[uint64]any{1: []byte{1, 2, 3}, 2: "/tmp/x", 3: uint64(10)}),
			Ls: []LsPiece{{ID: 1, Part: 1, Last: true, Path: "/", Sep: "/", Entries: []LsEntry{
				{Name: "etc", Type: 2, Size: &size, X: map[string]any{"inode": uint64(12)}},
			}}}},
		ChunkItem{T: ItemChunk, Xfer: task, Off: 0, Data: bytes.Repeat([]byte("ab"), 1000), Ctx: []byte("c")},
		ErrItem{T: ItemErr, Code: 3, Msg: "no", Item: &one, Task: task},
		TunnelItem{T: ItemTunnel, Task: task, Stream: 1, Kind: 3, Path: "/bin/sh", Args: []string{"-c", "id"}, Rows: 24, Cols: 80},
		DelegateItem{T: ItemDelegate, N: 1, Task: task, Step: 1, ID: task, Frame: []byte{1, 2, 3},
			Values:      map[string]any{"host": "10.0.0.1", "port": uint64(443)},
			Credentials: map[string]Credential{"c1": {ID: "c1", Type: "password", Username: "u", Password: "p"}},
			Failure:     &LinkFailure{Kind: LinkFailTimeout, Msg: "slow"}},
		FeedbackItem{T: ItemFeedback, ID: task, Level: 2, Msg: "warn"},
	)
	for _, want := range []string{
		`"blob":{"$b":"/wA="}`,                // bytes in an x: open
		`"5":"aGVsbG8A"`,                      // a result's out: bytes, plain
		`"7":{"1":{"$b":"AQID"},"2":"/tmp/x"`, // a result's data: open, numbered
		`"f":2.0`,                             // a float keeps its fraction
		`"user":`,                             // never: User is key 5
		`"4":{"1":{"$b":"CQkJCQkJCQkJCQkJCQkJCQ=="},"2":"a.txt"`, // a file offer in args
		`"neg":-2`,
		`"5":"dom\\u \"q\""`,
		`"note":"ünï\n"`,
	} {
		has := strings.Contains(js, want)
		if want == `"user":` {
			has = !has
		}
		if !has {
			t.Errorf("JSON lacks %s:\n%s", want, js)
		}
	}
}

func TestJSONEnvelopeEveryItemType(t *testing.T) {
	for typ, name := range itemNames {
		if _, ok := itemTypes[typ]; !ok {
			t.Errorf("item %d (%s) has no struct for the JSON envelope", typ, name)
		}
	}
	for typ, rt := range itemTypes {
		s := shapeOf(rt)
		if s.kind != shapeStruct || !s.intKeys || s.fields[uint64(0)] == nil {
			t.Errorf("item %d: %s is not a struct with numbered keys and key 0", typ, rt)
		}
	}
}

func TestJSONEnvelopeOpen(t *testing.T) {
	// An item the protocol does not know is read as open: numbered names
	// stay numbers, {"$b"} is bytes, text stays text.
	raw := `{"0":99,"1":"text","2":{"$b":"AAE="},"3":{"a":1},"4":{"1":2}}`
	b, err := JSONEnvelope.ReadItem([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	var m map[uint64]any
	if err := jsonTreeDec.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m[0] != uint64(99) || m[1] != "text" || !bytes.Equal(m[2].([]byte), []byte{0, 1}) ||
		!reflect.DeepEqual(m[3], map[any]any{"a": uint64(1)}) || !reflect.DeepEqual(m[4], map[any]any{uint64(1): uint64(2)}) {
		t.Fatalf("read %#v", m)
	}
	back, err := JSONEnvelope.WriteItem(b)
	if err != nil || string(back) != raw {
		t.Fatalf("wrote %s, %v", back, err)
	}

	// {"$b"} where the types say bytes is taken too.
	b, err = JSONEnvelope.ReadItem([]byte(`{"0":12,"1":{"$b":"AAECAwQFBgcICQoLDA0ODw=="},"2":0,"3":"aGk="}`))
	var c ChunkItem
	if err != nil || UnmarshalCBOR(b, &c) != nil || string(c.Data) != "hi" || len(c.Xfer) != 16 {
		t.Fatalf("$b where bytes go: %+v, %v", c, err)
	}

	// An x whose one key is "$b" is a map, its place typed.
	h := mustCBOR(t, HelloItem{T: ItemHello, OS: "linux", Arch: "amd64", X: map[string]any{"$b": "x"}})
	js, err := JSONEnvelope.WriteItem(h)
	if err != nil {
		t.Fatal(err)
	}
	if back, err := JSONEnvelope.ReadItem(js); err != nil || !bytes.Equal(back, h) {
		t.Fatalf("x {$b}: %s, %v", js, err)
	}
	// Inside an x, a map whose one key is "$b" has no JSON form.
	h = mustCBOR(t, HelloItem{T: ItemHello, OS: "linux", Arch: "amd64", X: map[string]any{"m": map[string]any{"$b": "x"}}})
	if _, err := JSONEnvelope.WriteItem(h); err == nil {
		t.Fatal("an open map {$b: ...} written")
	}
}

func TestJSONEnvelopeRefuses(t *testing.T) {
	big := mustCBOR(t, map[uint64]any{0: uint64(99), 1: uint64(1 << 53)})
	if _, err := JSONEnvelope.WriteItem(big); err == nil {
		t.Error("an integer past 2^53 - 1 written")
	}
	deep := strings.Repeat("[", 17) + strings.Repeat("]", 17)
	for name, js := range map[string]string{
		"duplicate name":    `{"0":3,"0":3}`,
		"bytes not base64":  `{"0":3,"1":"not base64!","3":[]}`,
		"bytes unpadded":    `{"0":3,"1":"AAECAwQFBgcICQoLDA0ODw","3":[]}`,
		"big integer":       `{"0":3,"1":"AAECAwQFBgcICQoLDA0ODw==","4":9007199254740992}`,
		"infinite float":    `{"0":3,"x":1e999}`,
		"trailing":          `{"0":3} {}`,
		"bom":               "\ufeff{\"0\":3}",
		"invalid utf-8":     "{\"0\":3,\"x\":\"\xff\"}",
		"too deep":          `{"0":3,"x":` + deep + `}`,
		"numbered map name": `{"0":3,"1":"AAECAwQFBgcICQoLDA0ODw==","3":[{"0":8,"1":"AAECAwQFBgcICQoLDA0ODw==","2":1,"3":{"a":1}}]}`,
		"$b not text":       `{"0":3,"x":{"$b":1}}`,
		"not json":          `{"0":3`,
	} {
		if _, err := JSONEnvelope.ReadMessage([]byte(js)); err == nil {
			t.Errorf("%s: read", name)
		}
	}
	if _, err := JSONEnvelope.ReadMessage(make([]byte, MaxMinionMessageSize+1)); err == nil {
		t.Error("a message over the limit read")
	}
	// A float stays a float; an integer an integer.
	b, err := JSONEnvelope.ReadItem([]byte(`{"0":99,"1":1.5,"2":-3,"3":1e2,"4":-0}`))
	if err != nil {
		t.Fatal(err)
	}
	var m map[uint64]any
	if err := jsonTreeDec.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m[1] != 1.5 || m[2] != int64(-3) || m[3] != 100.0 || m[4] != uint64(0) {
		t.Fatalf("numbers %#v", m)
	}
}

// A chunk as JSON is a third larger, as the page says: a 512 KiB chunk
// fits the protocol's message limit.
func TestJSONEnvelopeChunkSize(t *testing.T) {
	total := uint64(1 << 20)
	chunk := ChunkItem{T: ItemChunk, Xfer: NewMessageID(), Off: 1 << 19, Data: make([]byte, 512<<10), Total: &total}
	msg := mustCBOR(t, MinionMessage{V: MinionMessageV3, ID: NewMessageID(), Items: []cbor.RawMessage{mustCBOR(t, chunk)}})
	js, err := JSONEnvelope.WriteMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	if ratio := float64(len(js)) / float64(len(msg)); ratio < 1.33 || ratio > 1.34 || len(js) > MaxMinionMessageSize {
		t.Fatalf("CBOR %d, JSON %d", len(msg), len(js))
	}
	if back, err := JSONEnvelope.ReadMessage(js); err != nil || !bytes.Equal(back, msg) {
		t.Fatalf("read back: %v", err)
	}
}

func TestPackInJSON(t *testing.T) {
	ok := true
	out := []byte(strings.Repeat("drwxr-xr-x 2 root root 4096 Nov  9 12:00 somedir\n", 4000))
	item := mustCBOR(t, ResultItem{T: ItemResult, Task: NewMessageID(), Seq: 1, Done: true, OK: &ok, Out: out})
	packed, did, err := PackIn(JSONEnvelope, item)
	if err != nil || !did {
		t.Fatalf("not packed: %v", err)
	}
	var p PackedItem
	if err := UnmarshalCBOR(packed, &p); err != nil {
		t.Fatal(err)
	}
	msg := mustCBOR(t, MinionMessage{V: MinionMessageV3, ID: NewMessageID(), Items: []cbor.RawMessage{packed}})
	js, err := JSONEnvelope.WriteMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := JSONEnvelope.WriteItem(item)
	if len(js) > len(plain)/4 {
		t.Fatalf("packed JSON message %d bytes, the item %d", len(js), len(plain))
	}
	back, err := JSONEnvelope.ReadMessage(js)
	if err != nil {
		t.Fatal(err)
	}
	var m MinionMessage
	if err := UnmarshalCBOR(back, &m); err != nil {
		t.Fatal(err)
	}
	UnpackItemsIn(JSONEnvelope, m.Items)
	if !bytes.Equal(m.Items[0], item) {
		t.Fatal("unpacked item differs")
	}
	// The packed data is the item's JSON, deflated: CBOR does not read it.
	if _, err := Unpack(packed, MaxMinionMessageSize); !errors.Is(err, ErrPackedBad) {
		t.Fatalf("CBOR unpack of a JSON packed item: %v", err)
	}
	if _, err := UnpackIn(JSONEnvelope, packed, len(plain)-1); !errors.Is(err, ErrPackedTooLarge) {
		t.Fatalf("room counted in JSON: %v", err)
	}
	if _, err := UnpackIn(JSONEnvelope, packed, len(plain)); err != nil {
		t.Fatalf("room of the JSON exactly: %v", err)
	}
	// Small items stay as they are.
	small := mustCBOR(t, GetTasksItem{T: ItemGetTasks, Max: five()})
	if _, did, _ := PackIn(JSONEnvelope, small); did {
		t.Fatal("a small item packed")
	}
}

func TestCoreEnvelope(t *testing.T) {
	for name, want := range map[string]MessageEnvelope{"": CBOREnvelope, "cbor": CBOREnvelope, "json": JSONEnvelope} {
		if e, ok := CoreEnvelope(name); !ok || e != want || (name != "" && e.Name() != name) {
			t.Errorf("%q: %v %v", name, e, ok)
		}
	}
	if _, ok := CoreEnvelope("acme.xml"); ok {
		t.Error("a factory's envelope is core's")
	}
}
