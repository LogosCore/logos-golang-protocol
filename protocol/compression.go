package protocol

import (
	"bytes"
	"compress/flate"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/fxamacker/cbor/v2"
)

// Compression (docs: contracts/minion-messages/wire-format/, Compression):
// a sender may send any item packed, deflated inside a packed item, which
// the receiver inflates and takes as the item it holds, in its place in the
// message. One item each, in a compression context of its own: what one
// item says never changes the size of another.

// CompressionDeflate is raw DEFLATE (RFC 1951), the one algorithm: a build
// schema's Compression names it, a build request's Compression says it is
// on.
const CompressionDeflate = "deflate"

// PackDeflate is CompressionDeflate's number, a packed item's alg.
const PackDeflate = 1

// Compressions are the algorithms a build schema may name.
var Compressions = []string{CompressionDeflate}

// IsCompression reports whether name is an algorithm the protocol has.
func IsCompression(name string) bool { return slices.Contains(Compressions, name) }

const (
	// PackMinSize is the smallest item a sender packs: a smaller one
	// gains little, and may grow.
	PackMinSize = 256
	// PackMinSaving: a sender packs an item only when its deflated form
	// is at least an eighth smaller (a compressed file, TLS in a tunnel,
	// shrinks less, and goes as it is).
	PackMinSaving = 8
)

// PackedItem is an item deflated (ItemPacked, both ways).
type PackedItem struct {
	T   int    `cbor:"0,keyasint"`
	Alg uint64 `cbor:"1,keyasint"`
	// Data is the item, as the message's envelope writes it, deflated.
	Data []byte `cbor:"2,keyasint"`
}

var (
	// ErrPackedTooLarge: a packed item that inflates past the room its
	// message has left: an err too_large.
	ErrPackedTooLarge = errors.New("the packed item inflates past the room its message has left")
	// ErrPackedBad: a packed item that does not read, does not inflate,
	// or holds no single item (or another packed one): an err bad_message.
	ErrPackedBad = errors.New("the packed item does not hold an item")
)

// Pack is item packed when that pays: PackMinSize bytes or more, and its
// deflated form at least an eighth smaller. Otherwise, and for an item that
// is packed already, it is item itself, and packed is false. The item is
// written in CBOR: PackIn for another envelope.
func Pack(item cbor.RawMessage) (out cbor.RawMessage, packed bool, err error) {
	return PackIn(CBOREnvelope, item)
}

// PackIn is Pack for a message env writes: the packed item holds the item
// as env writes it, deflated, and both sizes are env's (a packed item's
// data is base64 in JSON). The packed item is the protocol's form, CBOR,
// as the item is.
func PackIn(env MessageEnvelope, item cbor.RawMessage) (out cbor.RawMessage, packed bool, err error) {
	if ItemType(item) == ItemPacked {
		return item, false, nil
	}
	written, err := env.WriteItem(item)
	if err != nil {
		return nil, false, err
	}
	if len(written) < PackMinSize {
		return item, false, nil
	}
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return nil, false, err
	}
	if _, err := w.Write(written); err != nil {
		return nil, false, err
	}
	if err := w.Close(); err != nil {
		return nil, false, err
	}
	p, err := MarshalCBOR(PackedItem{T: ItemPacked, Alg: PackDeflate, Data: buf.Bytes()})
	if err != nil {
		return nil, false, err
	}
	pw, err := env.WriteItem(p)
	if err != nil {
		return nil, false, err
	}
	if len(pw) > len(written)-len(written)/PackMinSaving {
		return item, false, nil
	}
	return p, true, nil
}

// Unpack is the item a packed item holds, inflated into room bytes at most
// (the room its message has left: UnpackRoom). ErrPackedTooLarge past it;
// ErrPackedBad for one that does not read or inflate, or holds no single
// item of the protocol, or another packed one. The message is CBOR:
// UnpackIn for another envelope.
func Unpack(raw cbor.RawMessage, room int) (cbor.RawMessage, error) {
	return UnpackIn(CBOREnvelope, raw, room)
}

// UnpackIn is Unpack for a message env wrote: the item inflates to env's
// form, within room bytes of it, and is read back as CBOR.
func UnpackIn(env MessageEnvelope, raw cbor.RawMessage, room int) (cbor.RawMessage, error) {
	var p PackedItem
	if err := UnmarshalCBOR(raw, &p); err != nil || p.T != ItemPacked {
		return nil, ErrPackedBad
	}
	if p.Alg != PackDeflate {
		return nil, fmt.Errorf("%w: alg %d", ErrPackedBad, p.Alg)
	}
	r := flate.NewReader(bytes.NewReader(p.Data))
	defer func() { _ = r.Close() }()
	written, err := io.ReadAll(io.LimitReader(r, int64(max(room, 0))+1))
	switch {
	case err != nil:
		return nil, fmt.Errorf("%w: %v", ErrPackedBad, err)
	case len(written) > room:
		return nil, ErrPackedTooLarge
	}
	inner, err := env.ReadItem(written)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPackedBad, err)
	}
	switch t := ItemType(inner); t {
	case 0, ItemPacked:
		// No item (ItemType reads it with the formats' rules), or another
		// packed one.
		return nil, ErrPackedBad
	}
	return inner, nil
}

// UnpackRoom is the room item i of items may inflate into: the message's
// limit less the items before it.
func UnpackRoom(items []cbor.RawMessage, i int) int {
	return UnpackRoomIn(CBOREnvelope, items, i)
}

// UnpackRoomIn is UnpackRoom with the items before i counted as env writes
// them.
func UnpackRoomIn(env MessageEnvelope, items []cbor.RawMessage, i int) int {
	room := MaxMinionMessageSize
	for _, it := range items[:min(i, len(items))] {
		room -= writtenSize(env, it)
	}
	return room
}

// writtenSize is how large env writes item: its CBOR size when it does
// not write it.
func writtenSize(env MessageEnvelope, item cbor.RawMessage) int {
	if w, err := env.WriteItem(item); err == nil {
		return len(w)
	}
	return len(item)
}

// UnpackItems takes the packed items of a message in their places, in
// order, each in the room the items before it leave. One that does not
// unpack stays as it is: its receiver answers it (UnpackRoom and Unpack
// again say why), so a message's items keep their indexes.
func UnpackItems(items []cbor.RawMessage) {
	UnpackItemsIn(CBOREnvelope, items)
}

// UnpackItemsIn is UnpackItems for a message env wrote (UnpackRoomIn and
// UnpackIn say why one stays packed).
func UnpackItemsIn(env MessageEnvelope, items []cbor.RawMessage) {
	if !slices.ContainsFunc(items, func(it cbor.RawMessage) bool { return ItemType(it) == ItemPacked }) {
		return
	}
	room := MaxMinionMessageSize
	for i, raw := range items {
		if ItemType(raw) == ItemPacked {
			if inner, err := UnpackIn(env, raw, room); err == nil {
				items[i] = inner
			}
		}
		room -= writtenSize(env, items[i])
	}
}
