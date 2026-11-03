package protocol

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// The data of the results this package defines travels numbered, as every
// protocol map does: a minion encodes it with WireResultData, and core turns
// it into the named shape (NamedResultData) when it takes the part, so what
// core keeps, shows and serves keeps the names. A result a factory shapes
// itself, and every x, keeps text keys.

type fileDownloadWire struct {
	Xfer   []byte         `cbor:"1,keyasint"`
	Path   string         `cbor:"2,keyasint"`
	Size   uint64         `cbor:"3,keyasint"`
	SHA256 []byte         `cbor:"4,keyasint"`
	X      map[string]any `cbor:"5,keyasint,omitempty"`
}

type fileUploadWire struct {
	Xfer   []byte         `cbor:"1,keyasint"`
	Path   string         `cbor:"2,keyasint"`
	Size   uint64         `cbor:"3,keyasint"`
	SHA256 []byte         `cbor:"4,keyasint"`
	X      map[string]any `cbor:"5,keyasint,omitempty"`
}

type fileStreamWire struct {
	Xfer   []byte         `cbor:"1,keyasint"`
	Path   string         `cbor:"2,keyasint"`
	Size   uint64         `cbor:"3,keyasint"`
	SHA256 []byte         `cbor:"4,keyasint,omitempty"`
	X      map[string]any `cbor:"5,keyasint,omitempty"`
}

type dirWalkWire struct {
	Root    string         `cbor:"1,keyasint"`
	Folders uint64         `cbor:"2,keyasint"`
	Entries uint64         `cbor:"3,keyasint"`
	Unread  uint64         `cbor:"4,keyasint,omitempty"`
	Skipped uint64         `cbor:"5,keyasint,omitempty"`
	Current string         `cbor:"6,keyasint,omitempty"`
	X       map[string]any `cbor:"7,keyasint,omitempty"`
}

type volumesWire struct {
	Sep     string         `cbor:"1,keyasint"`
	Volumes []volumeWire   `cbor:"2,keyasint,omitempty"`
	X       map[string]any `cbor:"3,keyasint,omitempty"`
}

type volumeWire struct {
	Path     string         `cbor:"1,keyasint"`
	Kind     string         `cbor:"2,keyasint"`
	Device   string         `cbor:"3,keyasint,omitempty"`
	Label    string         `cbor:"4,keyasint,omitempty"`
	FS       string         `cbor:"5,keyasint,omitempty"`
	Size     *uint64        `cbor:"6,keyasint,omitempty"`
	Free     *uint64        `cbor:"7,keyasint,omitempty"`
	ReadOnly bool           `cbor:"8,keyasint,omitempty"`
	NoMedia  bool           `cbor:"9,keyasint,omitempty"`
	X        map[string]any `cbor:"10,keyasint,omitempty"`
}

func (v Volumes) wire() volumesWire {
	w := volumesWire{Sep: v.Sep, X: v.X}
	for _, vol := range v.Volumes {
		w.Volumes = append(w.Volumes, volumeWire(vol))
	}
	return w
}

func (w volumesWire) named() Volumes {
	v := Volumes{Sep: w.Sep, X: w.X}
	for _, vol := range w.Volumes {
		v.Volumes = append(v.Volumes, Volume(vol))
	}
	return v
}

// WireResultData encodes a result part's data as it travels: a
// FileDownload, FileUpload, FileStream, DirWalk or Volumes numbered,
// anything else (a factory's own shape) as ResultData does.
func WireResultData(v any) (cbor.RawMessage, error) {
	switch d := v.(type) {
	case FileDownload:
		v = fileDownloadWire(d)
	case *FileDownload:
		v = fileDownloadWire(*d)
	case FileUpload:
		v = fileUploadWire(d)
	case *FileUpload:
		v = fileUploadWire(*d)
	case FileStream:
		v = fileStreamWire(d)
	case *FileStream:
		v = fileStreamWire(*d)
	case DirWalk:
		v = dirWalkWire(d)
	case *DirWalk:
		v = dirWalkWire(*d)
	case Volumes:
		v = d.wire()
	case *Volumes:
		v = d.wire()
	}
	return ResultData(v)
}

// NamedResultData turns a part's data, as it came, into the named shape of
// its command's result (FileDownload, ...): what core keeps. Data of a
// result this package does not number comes back as it is.
func NamedResultData(result string, data cbor.RawMessage) (cbor.RawMessage, error) {
	if len(data) == 0 {
		return data, nil
	}
	var named any
	var err error
	switch result {
	case ResultFileDownload:
		var w fileDownloadWire
		err = cborDec.Unmarshal(data, &w)
		named = FileDownload(w)
	case ResultFileUpload:
		var w fileUploadWire
		err = cborDec.Unmarshal(data, &w)
		named = FileUpload(w)
	case ResultFileStream:
		var w fileStreamWire
		err = cborDec.Unmarshal(data, &w)
		named = FileStream(w)
	case ResultDirWalk:
		var w dirWalkWire
		err = cborDec.Unmarshal(data, &w)
		named = DirWalk(w)
	case ResultVolumes:
		var w volumesWire
		err = cborDec.Unmarshal(data, &w)
		named = w.named()
	default:
		return data, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", result, err)
	}
	return MarshalCBOR(named)
}
