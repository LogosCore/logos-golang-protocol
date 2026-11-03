package protocol

import (
	"errors"
	"fmt"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

// Volumes is a volumes part's data: some of the host's volumes, in the
// order the host has them. A minion may send them over several parts (a
// host with many mounts, a connection that carries little): core joins the
// parts' volumes in order, and the volumes of a task that ended done are
// all the host has. Sep is on every part.
type Volumes struct {
	// Sep is the host's path separator: "/" or "\".
	Sep     string   `cbor:"sep" json:"sep"`
	Volumes []Volume `cbor:"volumes,omitempty" json:"volumes,omitempty"`
	// X holds a factory's own fields.
	X map[string]any `cbor:"x,omitempty" json:"x,omitempty"`
}

// Volume is a file system the host has: a Windows drive, a mount on Unix.
type Volume struct {
	// Path is where its files are, absolute, as the host writes it: a
	// drive's root (C:\), a mount point (/, /boot).
	Path string `cbor:"path" json:"path"`
	// Kind is what holds it (VolumeFixed, ...).
	Kind string `cbor:"kind" json:"kind"`
	// Device is what it is mounted from, as the host names it: /dev/sda1,
	// a network share (\\server\share).
	Device string `cbor:"device,omitempty" json:"device,omitempty"`
	// Label is its name, where it has one.
	Label string `cbor:"label,omitempty" json:"label,omitempty"`
	// FS is its file system, as the host names it: NTFS, ext4.
	FS string `cbor:"fs,omitempty" json:"fs,omitempty"`
	// Size and Free are in bytes, Free what the minion's user may still
	// write; none where the host does not say (a drive with no medium).
	Size *uint64 `cbor:"size,omitempty" json:"size,omitempty"`
	Free *uint64 `cbor:"free,omitempty" json:"free,omitempty"`
	// ReadOnly: mounted, or made, read only.
	ReadOnly bool `cbor:"read_only,omitempty" json:"read_only,omitempty"`
	// NoMedia: a drive with nothing in it (an empty DVD drive or card
	// reader): no file system, size or free.
	NoMedia bool `cbor:"no_media,omitempty" json:"no_media,omitempty"`
	// X holds a factory's own fields.
	X map[string]any `cbor:"x,omitempty" json:"x,omitempty"`
}

// Volume kinds. A later version may add kinds: a reader takes one it does
// not know as VolumeOther.
const (
	// VolumeFixed is a disk that stays: a hard disk, an SSD.
	VolumeFixed = "fixed"
	// VolumeRemovable is one that is taken out: a USB stick, a card.
	VolumeRemovable = "removable"
	// VolumeOptical is a CD, DVD or Blu-ray drive.
	VolumeOptical = "optical"
	// VolumeNetwork is a share on another host: a mapped drive, NFS, SMB.
	VolumeNetwork = "network"
	// VolumeRAM is one held in memory: a RAM disk, tmpfs.
	VolumeRAM = "ram"
	// VolumeOther is any other: a container's overlay, one the host does
	// not say.
	VolumeOther = "other"
)

// ReadVolumes decodes a volumes part's data and checks it: its separator,
// and each volume's path, absolute on the host, and kind. Keys it does not
// know are ignored.
func ReadVolumes(_ uint64, data cbor.RawMessage) (*Volumes, error) {
	var v Volumes
	if err := cborDec.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("volumes: %w", err)
	}
	if v.Sep != "/" && v.Sep != `\` {
		return nil, errors.New(`volumes: sep is "/" or "\"`)
	}
	for i, vol := range v.Volumes {
		switch {
		case !absoluteOn(v.Sep, vol.Path):
			return nil, fmt.Errorf("volumes: volume %d: an absolute path, not %q", i, vol.Path)
		case vol.Kind == "":
			return nil, fmt.Errorf("volumes: volume %d (%s): no kind", i, vol.Path)
		}
	}
	return &v, nil
}

// absoluteOn reports whether path is absolute on a host of separator sep:
// from / on Unix; from a drive (C:\) or a share (\\server\share) on
// Windows.
func absoluteOn(sep, path string) bool {
	if sep == "/" {
		return strings.HasPrefix(path, "/")
	}
	return strings.HasPrefix(path, `\\`) || (len(path) >= 3 && path[1] == ':' && path[2] == '\\')
}
