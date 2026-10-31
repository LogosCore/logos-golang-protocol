package protocol

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
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

func TestHello(t *testing.T) {
	in := HelloItem{T: ItemHello, PID: 4242, OS: "linux", Arch: "amd64", Host: "web01", Integrity: "root",
		Addrs: []string{"10.0.0.5"}, X: map[string]any{"cfg": map[string]any{"jitter": uint64(3)}}}
	data, err := MarshalCBOR(in)
	if err != nil {
		t.Fatal(err)
	}
	var got HelloItem
	if err := UnmarshalCBOR(data, &got); err != nil {
		t.Fatal(err)
	}
	if err := got.Validate(); err != nil || got.PID != 4242 || got.Host != "web01" {
		t.Fatalf("hello %+v: %v", got, err)
	}
	if _, ok := got.X["cfg"].(map[string]any); !ok {
		t.Fatalf("x's maps decode as %T, not map[string]any", got.X["cfg"])
	}
	for _, bad := range []HelloItem{
		{OS: "linux", Arch: "amd64"},
		{PID: 1, Arch: "amd64"},
		{PID: 1, OS: "linux"},
		{PID: 1, OS: "linux", Arch: "amd64", Integrity: "admin"},
		{PID: 1, OS: "linux", Arch: "amd64", SID: []byte{1, 2, 3}},
		{PID: 1, OS: "linux", Arch: "amd64", Sleep: &Sleep{Interval: 0}},
		{PID: 1, OS: "linux", Arch: "amd64", Sleep: &Sleep{Interval: 1000, Jitter: 101}},
	} {
		if bad.Validate() == nil {
			t.Fatalf("%+v passed", bad)
		}
	}
}

func TestSleepUpdate(t *testing.T) {
	data, _ := MarshalCBOR(SleepUpdateItem{T: ItemSleepUpdate, Interval: 60000, Jitter: 20})
	var got SleepUpdateItem
	if err := UnmarshalCBOR(data, &got); err != nil || got.Sleep() != (Sleep{Interval: 60000, Jitter: 20}) || got.Sleep().Validate() != nil {
		t.Fatalf("%+v: %v", got, err)
	}
	h := HelloItem{T: ItemHello, PID: 1, OS: "linux", Arch: "amd64", Sleep: &Sleep{Interval: 1000, Jitter: 20}}
	data, _ = MarshalCBOR(h)
	var back HelloItem
	if err := UnmarshalCBOR(data, &back); err != nil || back.Sleep == nil || *back.Sleep != *h.Sleep || back.Validate() != nil {
		t.Fatalf("hello's sleep: %+v %v", back.Sleep, err)
	}
}

func TestGetTasks(t *testing.T) {
	one := uint64(1)
	data, _ := MarshalCBOR(GetTasksItem{T: ItemGetTasks, Max: &one})
	var got GetTasksItem
	if err := UnmarshalCBOR(data, &got); err != nil || got.Max == nil || *got.Max != 1 || got.Validate() != nil {
		t.Fatalf("%+v: %v", got, err)
	}
	data, _ = MarshalCBOR(GetTasksItem{T: ItemGetTasks})
	got = GetTasksItem{}
	if err := UnmarshalCBOR(data, &got); err != nil || got.Max != nil {
		t.Fatalf("no max: %+v %v", got, err)
	}
	zero := uint64(0)
	if (GetTasksItem{T: ItemGetTasks, Max: &zero}).Validate() == nil {
		t.Fatal("max 0 passed")
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

func TestTaskItems(t *testing.T) {
	id := bytes.Repeat([]byte{7}, 16)
	task := TaskItem{T: ItemTask, Task: id, Cmd: "shell", Args: map[string]any{"command": "whoami", "timeout": uint64(30000)}}
	raw, err := MarshalCBOR(task)
	if err != nil {
		t.Fatal(err)
	}
	var back TaskItem
	if err := UnmarshalCBOR(raw, &back); err != nil || back.Validate() != nil || ItemType(raw) != ItemTask {
		t.Fatalf("task round trip: %+v, %v", back, err)
	}
	if back.Args["command"] != "whoami" {
		t.Fatalf("args %v", back.Args)
	}
	for name, bad := range map[string]TaskItem{
		"short id": {T: ItemTask, Task: id[:8], Cmd: "ls"},
		"bad cmd":  {T: ItemTask, Task: id, Cmd: "Shell!"},
	} {
		if bad.Validate() == nil {
			t.Errorf("%s: valid", name)
		}
	}
	if (CancelItem{T: ItemCancel, Task: id}).Validate() != nil || (CancelItem{T: ItemCancel}).Validate() == nil {
		t.Fatal("cancel validation")
	}
}

func TestResultItems(t *testing.T) {
	id := bytes.Repeat([]byte{9}, 16)
	ok, exit := true, int64(1)
	data, err := ResultData(map[string]any{"entries": []any{"a", "b"}})
	if err != nil {
		t.Fatal(err)
	}
	done := ResultItem{T: ItemResult, Task: id, Seq: 2, Done: true, OK: &ok, Out: []byte{0xff, 'a'}, Exit: &exit, Data: data}
	raw, err := MarshalCBOR(done)
	if err != nil {
		t.Fatal(err)
	}
	var back ResultItem
	if err := UnmarshalCBOR(raw, &back); err != nil || back.Validate() != nil {
		t.Fatalf("result round trip: %+v, %v", back, err)
	}
	if !bytes.Equal(back.Out, done.Out) || *back.Exit != 1 || !*back.OK || back.Seq != 2 {
		t.Fatalf("result %+v", back)
	}
	// The data comes through as it was sent.
	if !bytes.Equal(back.Data, data) {
		t.Fatalf("data %x, sent %x", back.Data, data)
	}
	if (ResultItem{T: ItemResult, Task: id, Data: []byte{0x82, 1, 2}}).Validate() == nil {
		t.Fatal("data that is an array passed")
	}
	if _, err := ResultData([]int{1}); err == nil {
		t.Fatal("ResultData took an array")
	}
	if (ResultItem{T: ItemResult, Task: id, Out: []byte("part")}).Validate() != nil {
		t.Fatal("a part before the last is valid without ok")
	}
	for name, bad := range map[string]ResultItem{
		"short id":         {T: ItemResult, Task: id[:3], Done: true, OK: &ok},
		"done without ok":  {T: ItemResult, Task: id, Done: true},
		"ok before done":   {T: ItemResult, Task: id, OK: &ok},
		"exit before done": {T: ItemResult, Task: id, Exit: &exit},
	} {
		if bad.Validate() == nil {
			t.Errorf("%s: valid", name)
		}
	}
}

func TestAckItems(t *testing.T) {
	id := bytes.Repeat([]byte{1}, 16)
	next := uint64(512)
	for name, c := range map[string]struct {
		ack AckItem
		ok  bool
	}{
		"tasks":             {AckItem{T: ItemAck, Tasks: [][]byte{id, id}}, true},
		"transfer":          {AckItem{T: ItemAck, Xfer: id, Next: &next}, true},
		"short task":        {AckItem{T: ItemAck, Tasks: [][]byte{id[:4]}}, false},
		"xfer without next": {AckItem{T: ItemAck, Xfer: id}, false},
	} {
		if got := c.ack.Validate() == nil; got != c.ok {
			t.Errorf("%s: valid=%v", name, got)
		}
	}
}

// A result's data may hold more than a message's 256 items: an ls of a big
// directory. The 256 is the message's items, checked by ValidateMessageHead.
func TestResultDataPastTheItemLimit(t *testing.T) {
	entries := make([]any, 1000)
	for i := range entries {
		entries[i] = map[string]any{"name": fmt.Sprintf("f%d", i)}
	}
	ok := true
	data, err := ResultData(map[string]any{"entries": entries})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalCBOR(ResultItem{T: ItemResult, Task: make([]byte, 16), Done: true, OK: &ok, Data: data})
	if err != nil {
		t.Fatal(err)
	}
	msg, _ := MarshalCBOR(MinionMessage{V: MinionMessageV1, ID: make([]byte, 16), Items: []cbor.RawMessage{raw}})
	var back MinionMessage
	if err := UnmarshalCBOR(msg, &back); err != nil {
		t.Fatalf("a message with a 1000-entry result: %v", err)
	}
	var r ResultItem
	var got map[string]any
	if err := UnmarshalCBOR(back.Items[0], &r); err != nil {
		t.Fatalf("result: %v", err)
	}
	if err := UnmarshalCBOR(r.Data, &got); err != nil || len(got["entries"].([]any)) != 1000 {
		t.Fatalf("result data: %v", err)
	}
	if ValidateMessageHead(MinionMessageV1, make([]byte, 16), nil, MaxMinionMessageItems+1) == nil {
		t.Fatal("more than 256 items passed")
	}
}
