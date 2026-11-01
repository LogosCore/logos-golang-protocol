package protocol

import (
	"bytes"
	"testing"
)

func TestConnFrame(t *testing.T) {
	id := bytes.Repeat([]byte{9}, 16)
	b, err := EncodeConnFrame(ConnFrame{ID: id, Data: []byte("sealed")})
	if err != nil {
		t.Fatal(err)
	}
	if got := keysOfCBOR(t, b); len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Fatalf("keys %v", got)
	}
	f, err := DecodeConnFrame(b)
	if err != nil || !bytes.Equal(f.ID, id) || string(f.Data) != "sealed" {
		t.Fatalf("%+v %v", f, err)
	}
	for name, bad := range map[string]ConnFrame{"short id": {ID: id[:8], Data: []byte{1}}, "no message": {ID: id}} {
		if _, err := EncodeConnFrame(bad); err == nil {
			t.Errorf("%s: encoded", name)
		}
	}
	if _, err := DecodeConnFrame([]byte{0xa1, 0x01, 0x41, 0x00}); err == nil {
		t.Error("a frame with a 1-byte id decoded")
	}
}
