package protocol

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func frameKeys(t *testing.T) AES256CBCHMACSHA256Material {
	t.Helper()
	k := AES256CBCHMACSHA256Material{EncKey: make([]byte, 32), MACKey: make([]byte, 32)}
	_, _ = rand.Read(k.EncKey)
	_, _ = rand.Read(k.MACKey)
	return k
}

var frameID = [16]byte{0x5b, 0x0c, 0x4f, 0x6e, 0x8a, 0x1d, 0x4c, 0x2b, 0x9e, 0x7f, 0x3d, 0x2a, 0x1b, 0x0c, 0x9e, 0x8f}

func TestFrameRoundTrip(t *testing.T) {
	keys := frameKeys(t)
	for _, size := range []int{0, 1, 15, 16, 17, 1000} {
		msg := bytes.Repeat([]byte{0xa5}, size)
		frame, err := SealFrame(keys, frameID, FrameMinionToCore, msg)
		if err != nil {
			t.Fatal(err)
		}
		pad := 16 - size%16
		if len(frame) != size+pad+frameFixed || frame[16] != FrameV1 || frame[len(frame)-33] != FrameMinionToCore {
			t.Fatalf("size %d: frame of %d bytes, ver %x, dir %x", size, len(frame), frame[16], frame[len(frame)-33])
		}
		got, err := OpenFrame(keys, frameID, FrameMinionToCore, frame)
		if err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("size %d: %x %v", size, got, err)
		}
	}
	a, _ := SealFrame(keys, frameID, FrameMinionToCore, []byte("same"))
	b, _ := SealFrame(keys, frameID, FrameMinionToCore, []byte("same"))
	if bytes.Equal(a[:16], b[:16]) {
		t.Fatal("an IV repeated")
	}
}

// Any change refuses the frame: every byte, the id it was sent under, the
// direction it is opened for, the keys.
func TestFrameRefusals(t *testing.T) {
	keys := frameKeys(t)
	frame, _ := SealFrame(keys, frameID, FrameMinionToCore, []byte("stage me"))
	for i := range frame {
		bad := bytes.Clone(frame)
		bad[i] ^= 0x01
		if _, err := OpenFrame(keys, frameID, FrameMinionToCore, bad); !errors.Is(err, ErrFrame) {
			t.Fatalf("byte %d flipped: %v", i, err)
		}
	}
	other := frameID
	other[0] ^= 1
	if _, err := OpenFrame(keys, other, FrameMinionToCore, frame); !errors.Is(err, ErrFrame) {
		t.Fatalf("another id: %v", err)
	}
	if _, err := OpenFrame(keys, frameID, FrameCoreToMinion, frame); !errors.Is(err, ErrFrame) {
		t.Fatalf("turned around: %v", err)
	}
	if _, err := OpenFrame(frameKeys(t), frameID, FrameMinionToCore, frame); !errors.Is(err, ErrFrame) {
		t.Fatalf("other keys: %v", err)
	}
	for _, n := range []int{0, MinFrameSize - 1, len(frame) - 1} {
		if _, err := OpenFrame(keys, frameID, FrameMinionToCore, frame[:n]); !errors.Is(err, ErrFrame) {
			t.Fatalf("%d bytes: %v", n, err)
		}
	}
	if _, err := SealFrame(AES256CBCHMACSHA256Material{EncKey: []byte("short")}, frameID, FrameMinionToCore, nil); err == nil {
		t.Fatal("sealed with short keys")
	}
}

func TestStageMessages(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, StageKeySize)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	stage, _ := MarshalCBOR(StageItem{T: ItemStage, Key: der, Corr: NewMessageID()})
	msg := MinionMessage{V: MinionMessageV1, ID: NewMessageID(), Items: []cbor.RawMessage{stage}}
	data, err := MarshalCBOR(msg)
	if err != nil {
		t.Fatal(err)
	}

	var got MinionMessage
	if err := UnmarshalCBOR(data, &got); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMessageHead(got.V, got.ID, got.Re, len(got.Items)); err != nil || len(got.Items) != 1 || ItemType(got.Items[0]) != ItemStage {
		t.Fatalf("message %+v: %v", got, err)
	}
	var item StageItem
	if err := UnmarshalCBOR(got.Items[0], &item); err != nil {
		t.Fatal(err)
	}
	pub, err := ParseStageKey(item.Key)
	if err != nil {
		t.Fatal(err)
	}

	material, _ := MarshalCBOR(frameKeys(t))
	sealed, err := EncryptStageKeys(pub, material)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := DecryptStageKeys(priv, sealed)
	if err != nil || !bytes.Equal(opened, material) {
		t.Fatalf("stage keys: %v", err)
	}
	var keys AES256CBCHMACSHA256Material
	if err := UnmarshalCBOR(opened, &keys); err != nil || len(keys.EncKey) != 32 || len(keys.MACKey) != 32 {
		t.Fatalf("keys %+v: %v", keys, err)
	}

	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	smallDER, _ := x509.MarshalPKIXPublicKey(&small.PublicKey)
	if _, err := ParseStageKey(smallDER); err == nil {
		t.Fatal("an RSA-1024 stage key was taken")
	}
}

// The subset: no duplicate keys, no indefinite lengths, no tags, a head with
// exactly one of id and re.
func TestCBORRules(t *testing.T) {
	var m MinionMessage
	for name, h := range map[string]string{
		"duplicate key":      "a2617601617601",                         // {"v": 1, "v": 1}
		"indefinite map":     "bf617601ff",                             // {_ "v": 1}
		"tag":                "a16176c11a6553f100",                     // {"v": 1(1700000000)}
		"invalid UTF-8 text": "a1617663ff00ff",                         // {"v": "\xff\x00\xff"}
		"huge claim":         "a161695bffffffffffffffff",               // {"i": bytes(2^64-1)}
		"too deep":           "a1617681818181818181818181818181818100", // {"v": 17 nested arrays}
	} {
		data, _ := hex.DecodeString(h)
		if err := UnmarshalCBOR(data, &m); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	id := NewMessageID()
	for name, c := range map[string]struct {
		v      int
		id, re []byte
	}{
		"no id or re": {1, nil, nil},
		"both":        {1, id, id},
		"short id":    {1, id[:8], nil},
		"v2":          {2, id, nil},
	} {
		if err := ValidateMessageHead(c.v, c.id, c.re, 0); err == nil {
			t.Errorf("%s: valid", name)
		}
	}
	if err := ValidateMessageHead(1, nil, id, 1); err != nil {
		t.Errorf("a reply: %v", err)
	}
}
