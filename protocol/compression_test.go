package protocol

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// textResult is a result item with n bytes of text output, which deflates
// well.
func textResult(t *testing.T, n int) cbor.RawMessage {
	t.Helper()
	ok := true
	out := []byte(strings.Repeat("drwxr-xr-x  2 root root 4096 lib\n", n/33+1)[:n])
	b, err := MarshalCBOR(ResultItem{T: ItemResult, Task: bytes.Repeat([]byte{1}, 16), Seq: 1, Done: true, OK: &ok, Out: out})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// deflated is a packed item of raw data, whatever it holds.
func deflated(t *testing.T, alg uint64, data []byte) cbor.RawMessage {
	t.Helper()
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestSpeed)
	_, _ = w.Write(data)
	_ = w.Close()
	b, err := MarshalCBOR(PackedItem{T: ItemPacked, Alg: alg, Data: buf.Bytes()})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPackRoundTrip(t *testing.T) {
	item := textResult(t, 8000)
	p, packed, err := Pack(item)
	if err != nil || !packed {
		t.Fatalf("not packed: %v", err)
	}
	if ItemType(p) != ItemPacked || ItemName(ItemPacked) != "packed" || ItemPacked != 30 {
		t.Fatalf("type %d %q", ItemType(p), ItemName(ItemPacked))
	}
	if len(p) > len(item)/4 {
		t.Fatalf("%d bytes packed of %d", len(p), len(item))
	}
	back, err := Unpack(p, MaxMinionMessageSize)
	if err != nil || !bytes.Equal(back, item) {
		t.Fatalf("unpacked %d bytes, err %v", len(back), err)
	}
}

// What gains too little goes as it is: a small item, one that does not
// shrink an eighth, and one packed already.
func TestPackOnlyWhenItPays(t *testing.T) {
	small := textResult(t, 100)
	random := make([]byte, 4000)
	_, _ = rand.Read(random)
	ok := true
	noise, _ := MarshalCBOR(ResultItem{T: ItemResult, Task: bytes.Repeat([]byte{1}, 16), Seq: 1, OK: &ok, Out: random})
	packedAlready, _, _ := Pack(textResult(t, 8000))
	for name, item := range map[string]cbor.RawMessage{"small": small, "incompressible": noise, "packed": packedAlready} {
		out, packed, err := Pack(item)
		if err != nil || packed || !bytes.Equal(out, item) {
			t.Errorf("%s: packed %v, err %v", name, packed, err)
		}
	}
}

func TestUnpackRefuses(t *testing.T) {
	item := textResult(t, 8000)
	p, _, _ := Pack(item)
	if _, err := Unpack(p, len(item)-1); !errors.Is(err, ErrPackedTooLarge) {
		t.Errorf("past the room: %v", err)
	}
	if got, err := Unpack(p, len(item)); err != nil || !bytes.Equal(got, item) {
		t.Errorf("in exactly the room: %v", err)
	}
	for name, raw := range map[string]cbor.RawMessage{
		"another alg":     deflated(t, 2, item),
		"not deflate":     mustCBOR(t, PackedItem{T: ItemPacked, Alg: PackDeflate, Data: []byte("not deflate at all")}),
		"no item inside":  deflated(t, PackDeflate, []byte{0x83, 1, 2, 3}),
		"two items":       deflated(t, PackDeflate, append(append([]byte{}, item...), item...)),
		"packed inside":   deflated(t, PackDeflate, p),
		"not packed":      item,
		"a broken packed": cbor.RawMessage{0xa1, 0x00},
	} {
		if _, err := Unpack(raw, MaxMinionMessageSize); !errors.Is(err, ErrPackedBad) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func mustCBOR(t *testing.T, v any) cbor.RawMessage {
	t.Helper()
	b, err := MarshalCBOR(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A message's packed items are taken in place, each in the room the items
// before it leave; one that does not unpack stays.
func TestUnpackItems(t *testing.T) {
	a, b := textResult(t, 8000), textResult(t, 9000)
	pa, _, _ := Pack(a)
	pb, _, _ := Pack(b)
	bad := deflated(t, 2, a)
	get, _ := MarshalCBOR(GetTasksItem{T: ItemGetTasks})
	items := []cbor.RawMessage{get, pa, bad, pb}
	UnpackItems(items)
	if !bytes.Equal(items[0], get) || !bytes.Equal(items[1], a) || !bytes.Equal(items[2], bad) || !bytes.Equal(items[3], b) {
		t.Fatalf("items %v", items)
	}
	if room := UnpackRoom(items, 3); room != MaxMinionMessageSize-len(get)-len(a)-len(bad) {
		t.Fatalf("room %d", room)
	}
	// The room runs out: the items before count inflated.
	big := textResult(t, MaxMinionMessageSize-1000)
	pbig, packed, _ := Pack(big)
	if !packed {
		t.Fatal("big not packed")
	}
	items = []cbor.RawMessage{pb, pbig}
	UnpackItems(items)
	if !bytes.Equal(items[0], b) || ItemType(items[1]) != ItemPacked {
		t.Fatal("the second should not fit the room the first leaves")
	}
	if _, err := Unpack(items[1], UnpackRoom(items, 1)); !errors.Is(err, ErrPackedTooLarge) {
		t.Fatalf("why: %v", err)
	}
}

func TestBuildSchemaCompression(t *testing.T) {
	s := exampleBuildSchema(t)
	s.Compression = []string{CompressionDeflate}
	if err := ValidateBuildSchema(s); err != nil {
		t.Fatal(err)
	}
	for _, c := range [][]string{{"zstd"}, {CompressionDeflate, CompressionDeflate}} {
		s.Compression = c
		if err := ValidateBuildSchema(s); err == nil {
			t.Errorf("%v taken", c)
		}
	}
}
