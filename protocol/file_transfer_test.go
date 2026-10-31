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
