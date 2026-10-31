package protocol

import (
	"bytes"
	"strings"
	"testing"
)

func TestChunkItem(t *testing.T) {
	xfer, task := bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 16)
	total := uint64(10)
	ok := []ChunkItem{
		{T: ItemChunk, Xfer: xfer, Off: 0, Data: []byte("hello"), Total: &total, Task: task, Name: "/etc/hosts"},
		{T: ItemChunk, Xfer: xfer, Off: 5, Data: []byte("world"), SHA256: make([]byte, 32)},
		{T: ItemChunk, Xfer: xfer, Off: 0, Data: nil, Total: new(uint64), Task: task, SHA256: make([]byte, 32)}, // empty file
	}
	for i, c := range ok {
		if err := c.Validate(); err != nil {
			t.Errorf("%d: %v", i, err)
		}
	}
	for want, c := range map[string]ChunkItem{
		"xfer is 16 bytes":              {Xfer: []byte{1}},
		"over":                          {Xfer: xfer, Off: 1, Data: make([]byte, MaxChunkData+1)},
		"sha256 is 32 bytes":            {Xfer: xfer, Off: 1, SHA256: []byte{1}},
		"the first says total and task": {Xfer: xfer, Off: 0, Data: []byte("x")},
		"only the first says":           {Xfer: xfer, Off: 3, Total: &total},
		"more data than total":          {Xfer: xfer, Off: 0, Data: make([]byte, 11), Total: &total, Task: task},
	} {
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v", want, err)
		}
	}
	// It goes through a message as it is.
	raw, err := MarshalCBOR(ok[0])
	if err != nil {
		t.Fatal(err)
	}
	var back ChunkItem
	if err := UnmarshalCBOR(raw, &back); err != nil || back.Validate() != nil || string(back.Data) != "hello" || *back.Total != 10 {
		t.Fatalf("round trip: %+v %v", back, err)
	}
}

func TestReadFileDownload(t *testing.T) {
	good, _ := ResultData(FileDownload{Xfer: make([]byte, 16), Path: "/etc/hosts", Size: 3, SHA256: make([]byte, 32)})
	if f, err := ReadFileDownload(0, good); err != nil || f.Path != "/etc/hosts" || f.Size != 3 {
		t.Fatalf("%+v %v", f, err)
	}
	bad, _ := ResultData(FileDownload{Xfer: make([]byte, 16), Path: "/x", SHA256: []byte{1}})
	if _, err := ReadFileDownload(0, bad); err == nil {
		t.Error("a short sha256 passed")
	}
	if a, ok := KnownAction(ActionDownloadFile); !ok || a.Result != ResultFileDownload || a.Params["path"] != FieldString || !KnownResult(ResultFileDownload) {
		t.Errorf("download_file: %+v %v", a, ok)
	}
}

// A command takes one file param at most; it has no default.
func TestCommandFileParam(t *testing.T) {
	file := FieldSpec{Key: "file", Type: FieldFile, Required: true, Accept: []string{".exe"}}
	if err := validateBuildCommand(BuildCommand{ID: "put", Params: []FieldSpec{file}}, nil); err != nil {
		t.Fatalf("a file param: %v", err)
	}
	two := BuildCommand{ID: "put", Params: []FieldSpec{file, {Key: "other", Type: FieldFile}}}
	if err := validateBuildCommand(two, nil); err == nil || !strings.Contains(err.Error(), "one file param at most") {
		t.Fatalf("two: %v", err)
	}
	if err := validateFieldSpec(file); err == nil {
		t.Fatal("a file field outside build schemas")
	}
}

func TestArgFile(t *testing.T) {
	offer := FileOffer{Xfer: bytes.Repeat([]byte{1}, 16), Name: "tool.exe", Size: 5, SHA256: make([]byte, 32)}
	// As a minion decodes a task: the args from CBOR, the offer a map.
	raw, err := MarshalCBOR(map[string]any{"file": offer})
	if err != nil {
		t.Fatal(err)
	}
	var args map[string]any
	if err := cborDec.Unmarshal(raw, &args); err != nil {
		t.Fatal(err)
	}
	got, err := ArgFile(args, "file")
	if err != nil || got.Name != "tool.exe" || got.Size != 5 || !bytes.Equal(got.Xfer, offer.Xfer) {
		t.Fatalf("ArgFile: %+v %v", got, err)
	}
	for name, o := range map[string]FileOffer{
		"short xfer": {Xfer: []byte{1}, Name: "a", SHA256: make([]byte, 32)},
		"a path":     {Xfer: offer.Xfer, Name: "../a", SHA256: offer.SHA256},
		"a \\ path":  {Xfer: offer.Xfer, Name: `c:\a`, SHA256: offer.SHA256},
		"no sha256":  {Xfer: offer.Xfer, Name: "a"},
	} {
		if _, err := ArgFile(map[string]any{"file": o}, "file"); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
	if _, err := ArgFile(map[string]any{}, "file"); err == nil {
		t.Error("none: taken")
	}
}

func TestReadFileUpload(t *testing.T) {
	data, _ := ResultData(FileUpload{Xfer: make([]byte, 16), Path: "/tmp/a", Size: 3, SHA256: make([]byte, 32)})
	if f, err := ReadFileUpload(0, data); err != nil || f.Path != "/tmp/a" || f.Size != 3 {
		t.Fatalf("%+v %v", f, err)
	}
	bad, _ := ResultData(FileUpload{Xfer: make([]byte, 16), SHA256: make([]byte, 32)})
	if _, err := ReadFileUpload(0, bad); err == nil {
		t.Fatal("no path: taken")
	}
}

func TestStreamItems(t *testing.T) {
	next := uint64(0)
	if err := (AckItem{T: ItemAck, Xfer: make([]byte, 16), Next: &next, Hold: true}).Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (AckItem{T: ItemAck, Hold: true}).Validate(); err == nil {
		t.Fatal("hold without xfer: taken")
	}
	// The announcement: the first chunk, no data.
	total := uint64(5 << 30)
	if err := (ChunkItem{T: ItemChunk, Xfer: make([]byte, 16), Total: &total, Task: make([]byte, 16), Name: "/a"}).Validate(); err != nil {
		t.Fatal(err)
	}
	data, _ := ResultData(FileStream{Xfer: make([]byte, 16), Path: "/a", Size: total})
	if f, err := ReadFileStream(0, data); err != nil || f.Size != total || f.SHA256 != nil {
		t.Fatalf("%+v %v", f, err)
	}
	bad, _ := ResultData(FileStream{Xfer: make([]byte, 16), Path: "/a", SHA256: []byte{1}})
	if _, err := ReadFileStream(0, bad); err == nil {
		t.Fatal("a short sha256: taken")
	}
	if a, ok := KnownAction(ActionStreamFile); !ok || a.Result != ResultFileStream {
		t.Fatal("stream_file")
	}
}
