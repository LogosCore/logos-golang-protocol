package protocol

import (
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/fxamacker/cbor/v2"
)

// ProcessList is a process_list part's data (docs:
// contracts/task-results-and-actions.md, process_list): some of the host's
// processes, those the minion sees, in any order. A minion may send them
// over several parts: core joins the parts' processes in order, and shows a
// pid that comes twice once, as it first came. Sep is on every part.
type ProcessList struct {
	// Sep is the host's path separator: "/" or "\".
	Sep       string    `cbor:"sep" json:"sep"`
	Processes []Process `cbor:"processes,omitempty" json:"processes,omitempty"`
	// X holds a factory's own fields.
	X map[string]any `cbor:"x,omitempty" json:"x,omitempty"`
}

// Process is one of the host's processes, as the minion could read it: a pid
// and a name at least (one it may not open has no more).
type Process struct {
	PID uint64 `cbor:"pid" json:"pid"`
	// PPID is its parent's pid, as the host keeps it, the parent alive or
	// not; nil for none.
	PPID *uint64 `cbor:"ppid,omitempty" json:"ppid,omitempty"`
	// Name is its image's name, without a path: sshd, svchost.exe.
	Name string `cbor:"name" json:"name"`
	// Path is its executable, absolute, as the host writes it.
	Path string `cbor:"path,omitempty" json:"path,omitempty"`
	// Cmdline is its command line as the host shows it: a Windows process's
	// own, a Unix one's args joined by spaces.
	Cmdline string `cbor:"cmdline,omitempty" json:"cmdline,omitempty"`
	// User is who it runs as, as the host names them: root, CORP\ann.
	User string `cbor:"user,omitempty" json:"user,omitempty"`
	// Started is when it started, unix seconds.
	Started *int64 `cbor:"started,omitempty" json:"started,omitempty"`
	// Session is the Windows session it runs in, 0 for services; nil
	// elsewhere.
	Session *uint64 `cbor:"session,omitempty" json:"session,omitempty"`
	// Integrity is its level by name, as the hello's (IntegrityName): low,
	// medium, high or system (its token's, on Windows), root or user (its
	// effective uid, on Unix).
	Integrity string `cbor:"integrity,omitempty" json:"integrity,omitempty"`
	// Arch is GOARCH-style, as the hello's: 386 for a 32-bit process on
	// 64-bit Windows.
	Arch    string  `cbor:"arch,omitempty" json:"arch,omitempty"`
	Threads *uint64 `cbor:"threads,omitempty" json:"threads,omitempty"`
	// Memory is the bytes it holds resident: its working set, its RSS.
	Memory *uint64 `cbor:"memory,omitempty" json:"memory,omitempty"`
	// CPUTime is the milliseconds of CPU it used, user and kernel.
	CPUTime *uint64 `cbor:"cpu_time,omitempty" json:"cpu_time,omitempty"`
	// State is what it does (ProcessRunning, ...); "" where the minion does
	// not say.
	State string `cbor:"state,omitempty" json:"state,omitempty"`
	// X holds a factory's own fields.
	X map[string]any `cbor:"x,omitempty" json:"x,omitempty"`
}

// Process states (Process.State). They travel by number, ProcessRunning 1
// to ProcessZombie 5; a later version may add states, which a reader shows
// by their number ("state 9").
const (
	ProcessRunning  = "running"
	ProcessSleeping = "sleeping"
	// ProcessWaiting: in the kernel, uninterruptible (Linux's D).
	ProcessWaiting = "waiting"
	// ProcessStopped: by a signal, or with every thread suspended (Windows).
	ProcessStopped = "stopped"
	// ProcessZombie: ended, not yet reaped by its parent.
	ProcessZombie = "zombie"
)

// processStates are the states by number, from 1.
var processStates = []string{1: ProcessRunning, 2: ProcessSleeping, 3: ProcessWaiting, 4: ProcessStopped, 5: ProcessZombie}

// ProcessStateName is a state's name by its number: "" for none, "state 9"
// for one this version does not know.
func ProcessStateName(n uint64) string {
	switch {
	case n == 0:
		return ""
	case n < uint64(len(processStates)):
		return processStates[n]
	}
	return "state " + strconv.FormatUint(n, 10)
}

// processStateNumber is a state's number by its name: false for one this
// version does not know.
func processStateNumber(name string) (uint64, bool) {
	i := slices.Index(processStates, name)
	return uint64(max(i, 0)), i > 0
}

// integrityNumber is a level's number by its name (IntegrityName): false for
// one this version does not know.
func integrityNumber(name string) (uint64, bool) {
	for n, s := range integrityNames {
		if s == name {
			return uint64(n), true
		}
	}
	return 0, false
}

// ReadProcessList decodes a process_list part's data and checks it: its
// separator, and each process's name, and its path absolute on the host when
// it has one. Keys it does not know are ignored.
func ReadProcessList(_ uint64, data cbor.RawMessage) (*ProcessList, error) {
	var l ProcessList
	if err := cborDec.Unmarshal(data, &l); err != nil {
		return nil, fmt.Errorf("process_list: %w", err)
	}
	if l.Sep != "/" && l.Sep != `\` {
		return nil, errors.New(`process_list: sep is "/" or "\"`)
	}
	for i, p := range l.Processes {
		switch {
		case p.Name == "":
			return nil, fmt.Errorf("process_list: process %d (pid %d): no name", i, p.PID)
		case p.Path != "" && !absoluteOn(l.Sep, p.Path):
			return nil, fmt.Errorf("process_list: process %d (pid %d): an absolute path, not %q", i, p.PID, p.Path)
		}
	}
	return &l, nil
}
