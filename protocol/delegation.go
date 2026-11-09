package protocol

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// Delegation (docs: contracts/minion-messages/delegation/): a delegate is
// a minion of an operation that serves a channel kind's transport on its
// own host while a task of its runs (ActionDelegate, ActionReverseDelegate),
// and carries what a channel module would say to core inside its own
// messages, in delegate items (DelegateItem): the sync call's request and
// reply, the control link's call, open and answer, and a connection
// socket's frames and close. The minion it serves is not changed and is
// not told: it speaks its connection's channel kind as always, and cannot
// tell a delegate from the module. A delegate never reads what it carries:
// frames stay sealed with the delegated minion's keys.
//
// An item's keys 1 to 13 are those of the control link's frames
// (LinkFrame), for the same things; 11 and 14 (keys, acting) are an
// agentless kind's alone, and never in this item: agentless kinds are not
// delegated.

// Delegate steps: a delegate item's Step, what it is.
const (
	// DelegateSync: a minion's request, as the sync call carries it
	// (delegate → core, in a reverse_delegate task).
	DelegateSync = 1
	// DelegateReply: core's reply to a sync (core → delegate): Status
	// says what the sync call would have answered (200 with the frame, 204
	// nothing for the minion, else a refusal).
	DelegateReply = 2
	// DelegateCall: a call to a bind-call target (core → delegate, in a
	// delegate task), as the control link's.
	DelegateCall = 3
	// DelegateOpen: an open of a bind-persistent connection (core →
	// delegate, in a delegate task), as the control link's.
	DelegateOpen = 4
	// DelegateAnswer: the delegate's answer to a call or an open (delegate
	// → core), as the control link's: a call's what came back (a frame, or a
	// status and what answered), either's failure; an open's none, it
	// opened.
	DelegateAnswer = 5
	// DelegateFrame: a frame over a connection (both ways), as a connection
	// socket's; a reverse one's first from the delegate opens it.
	DelegateFrame = 6
	// DelegateClose: a connection is over (both ways): from the delegate,
	// it ended; from core, close it.
	DelegateClose = 7
)

var delegateStepNames = map[int]string{
	DelegateSync: "sync", DelegateReply: "reply", DelegateCall: "call", DelegateOpen: "open",
	DelegateAnswer: "answer", DelegateFrame: "frame", DelegateClose: "close",
}

// DelegateStepName is a step's name, for people: "step 9" for one this
// version does not know.
func DelegateStepName(s int) string {
	if n, ok := delegateStepNames[s]; ok {
		return n
	}
	return fmt.Sprintf("step %d", s)
}

// Delegate close reasons: a close's Reason.
const (
	// DelegateClosed: from the delegate, the connection ended (its minion,
	// its host or the network ended it); from core, close it.
	DelegateClosed = 1
	// DelegateNoConnection: the receiver does not have the connection: the
	// sender drops it.
	DelegateNoConnection = 2
	// DelegateTaskEnded: the task ended, or the delegate runs no such task.
	DelegateTaskEnded = 3
)

var delegateCloseNames = map[int]string{
	DelegateClosed: "closed", DelegateNoConnection: "no_connection", DelegateTaskEnded: "task_ended",
}

// DelegateCloseName is a close reason's name, for people: "reason 9" for
// one this version does not know.
func DelegateCloseName(r int) string {
	if n, ok := delegateCloseNames[r]; ok {
		return n
	}
	return fmt.Sprintf("reason %d", r)
}

// Delegation's limits.
const (
	// MaxDelegateFrame is the largest frame a delegate item carries, whole
	// or joined from pieces: the largest message, sealed, and room to spare.
	MaxDelegateFrame = 1 << 20
	// MaxDelegateDepth is how many delegates may be between a minion and a
	// channel module.
	MaxDelegateDepth = 4
	// MaxServes is how many channel kinds a delegate command serves.
	MaxServes = 16
	// MaxDelegateMsg caps a close's text, in bytes.
	MaxDelegateMsg = 256
	// MaxDelegateHead caps an answer's head: the first bytes of what
	// answered a call when it is not a minion message.
	MaxDelegateHead = 512
	// DelegateItemOverhead is what a delegate item takes besides its frame,
	// its values and its credentials, generously: what a sender keeps free
	// of a message's room for each item it puts there.
	DelegateItemOverhead = 160
)

// DelegateItem is one step of what a delegate carries (both ways): Step
// says which, Task the delegate's task, N the exchange or the connection
// it is about, numbered from 1 by the side that starts it (core in a
// delegate task, the delegate in a reverse_delegate task), never reused
// within the task.
type DelegateItem struct {
	T int    `cbor:"0,keyasint"`
	N uint64 `cbor:"1,keyasint"`
	// Values are a call's or an open's: the build connection's and the
	// target's, by the keys the channel declared, as the control link's.
	Values map[string]any `cbor:"2,keyasint,omitempty"`
	// ID is the id Frame is sent under (a build id, a temporary id, a
	// session id); Frame the sealed frame, or a piece of it (Off, Size),
	// never read by the delegate.
	ID    []byte `cbor:"3,keyasint,omitempty"`
	Frame []byte `cbor:"4,keyasint,omitempty"`
	// Deadline is a call's or an open's, in milliseconds: the transport's,
	// from when the delegate takes it.
	Deadline uint64 `cbor:"5,keyasint,omitempty"`
	// Status is an answer's, the transport's (an HTTP status); a reply's,
	// the sync call's (ReplyOK with a frame, ReplyNoContent, else a
	// refusal).
	Status int `cbor:"6,keyasint,omitempty"`
	// Failure is an answer's: the call or the open did not reach the
	// minion, and why (LinkFailUnreachable, ...).
	Failure *LinkFailure `cbor:"7,keyasint,omitempty"`
	// Head is an answer's: the first bytes of what answered a call, when it
	// is not a minion message (a 404, a WAF's page).
	Head []byte `cbor:"8,keyasint,omitempty"`
	// Peer is the minion's address as the delegate saw it, raw (4 bytes or
	// 16): a sync's, an answer's, a reverse connection's first frame's.
	Peer []byte `cbor:"9,keyasint,omitempty"`
	// Under is an open's: the id the minion speaks under on the connection.
	Under []byte `cbor:"10,keyasint,omitempty"`
	// Credentials are a call's or an open's: those of the values'
	// credential fields, by id. Logins are an answer's: how each fared.
	Credentials map[string]Credential `cbor:"12,keyasint,omitempty"`
	Logins      []LinkLogin           `cbor:"13,keyasint,omitempty"`
	Task        []byte                `cbor:"15,keyasint"`
	Step        int                   `cbor:"16,keyasint"`
	// Serve is which of the task's command's Serves the step is of, from
	// 1: on a call, an open, a sync, and a reverse connection's first frame.
	Serve uint64 `cbor:"17,keyasint,omitempty"`
	// Seq is a connection's frame's number in its direction, from 0: what
	// puts its pieces together.
	Seq uint64 `cbor:"18,keyasint,omitempty"`
	// Off and Size: a frame in pieces, where this piece starts and the
	// whole frame's length; Size 0: the frame is whole.
	Off  uint64 `cbor:"19,keyasint,omitempty"`
	Size uint64 `cbor:"20,keyasint,omitempty"`
	// Reason and Msg are a close's (DelegateClosed, ...).
	Reason int    `cbor:"21,keyasint,omitempty"`
	Msg    string `cbor:"22,keyasint,omitempty"`
}

// The sync call's statuses a reply carries.
const (
	ReplyOK        = 200
	ReplyNoContent = 204
)

// delegateFromDelegate and delegateFromCore are the steps each side sends.
var (
	delegateFromDelegate = []int{DelegateSync, DelegateAnswer, DelegateFrame, DelegateClose}
	delegateFromCore     = []int{DelegateReply, DelegateCall, DelegateOpen, DelegateFrame, DelegateClose}
)

// carriesFrame reports whether a step carries a frame.
func carriesFrame(step int) bool {
	switch step {
	case DelegateSync, DelegateReply, DelegateCall, DelegateAnswer, DelegateFrame:
		return true
	}
	return false
}

// Pieced reports whether the item carries a piece of a frame rather than a
// whole one.
func (d DelegateItem) Pieced() bool { return d.Size > 0 }

// Answerable reports whether a close can answer the item: its task and its
// number read.
func (d DelegateItem) Answerable() bool { return len(d.Task) == 16 && d.N > 0 }

// Validate checks the item as fromDelegate's (true: the delegate sent it;
// false: core did): its task, step and number, which keys its step takes,
// and its frame or piece.
func (d DelegateItem) Validate(fromDelegate bool) error {
	name := "delegate " + DelegateStepName(d.Step)
	switch {
	case len(d.Task) != 16:
		return errors.New("delegate: task is 16 bytes")
	case d.N == 0:
		return fmt.Errorf("%s: n is from 1", name)
	}
	sends := delegateFromCore
	if fromDelegate {
		sends = delegateFromDelegate
	}
	if !slices.Contains(sends, d.Step) {
		if _, known := delegateStepNames[d.Step]; !known {
			return fmt.Errorf("delegate: %s is not one this version knows", name)
		}
		who := "core"
		if fromDelegate {
			who = "a delegate"
		}
		return fmt.Errorf("%s: %s does not send it", name, who)
	}
	if err := d.validateFrame(name); err != nil {
		return err
	}
	if d.Peer != nil && len(d.Peer) != net.IPv4len && len(d.Peer) != net.IPv6len {
		return fmt.Errorf("%s: peer is 4 bytes or 16", name)
	}
	// Each step's keys: what it must have, and what it may not.
	has := map[string]bool{
		"values": d.Values != nil, "deadline": d.Deadline > 0, "status": d.Status != 0,
		"failure": d.Failure != nil, "head": d.Head != nil, "peer": d.Peer != nil, "under": d.Under != nil,
		"credentials": d.Credentials != nil, "logins": d.Logins != nil, "serve": d.Serve > 0,
		"reason": d.Reason != 0, "msg": d.Msg != "",
	}
	var may []string
	switch d.Step {
	case DelegateSync:
		may = []string{"serve", "peer"}
		if d.Serve == 0 {
			return fmt.Errorf("%s: serve is from 1", name)
		}
	case DelegateReply:
		may = []string{"status"}
		switch {
		case d.Status == ReplyOK && len(d.Frame) == 0:
			return fmt.Errorf("%s: 200 carries a frame", name)
		case d.Status != ReplyOK && len(d.Frame) > 0:
			return fmt.Errorf("%s: only 200 carries a frame", name)
		case d.Status < 200 || d.Status > 599:
			return fmt.Errorf("%s: status is the sync call's", name)
		}
	case DelegateCall, DelegateOpen:
		may = []string{"serve", "values", "deadline", "credentials"}
		if d.Step == DelegateOpen {
			may = append(may, "under")
		}
		switch {
		case d.Serve == 0:
			return fmt.Errorf("%s: serve is from 1", name)
		case d.Deadline == 0:
			return fmt.Errorf("%s: a deadline is required", name)
		case d.Under != nil && len(d.Under) != 16:
			return fmt.Errorf("%s: under is 16 bytes", name)
		}
	case DelegateAnswer:
		may = []string{"status", "failure", "head", "peer", "logins"}
		switch {
		case d.Failure != nil && (len(d.Frame) > 0 || d.Head != nil):
			return fmt.Errorf("%s: a failure carries no frame and no head", name)
		case d.Failure != nil && d.Failure.Kind < 1:
			return fmt.Errorf("%s: a failure has a kind", name)
		case d.Head != nil && len(d.Frame) > 0:
			return fmt.Errorf("%s: a head is for what is not a minion message", name)
		case len(d.Head) > MaxDelegateHead:
			return fmt.Errorf("%s: head longer than %d bytes", name, MaxDelegateHead)
		case d.Failure != nil && len(d.Failure.Msg) > MaxDelegateMsg:
			return fmt.Errorf("%s: failure longer than %d bytes", name, MaxDelegateMsg)
		}
	case DelegateFrame:
		if fromDelegate {
			may = []string{"serve", "peer"}
		}
		if len(d.Frame) == 0 {
			return fmt.Errorf("%s: a frame is required", name)
		}
	case DelegateClose:
		may = []string{"reason", "msg"}
		switch {
		case d.Reason < 1:
			return fmt.Errorf("%s: reason is 1 (closed) or more", name)
		case len(d.Msg) > MaxDelegateMsg:
			return fmt.Errorf("%s: msg longer than %d bytes", name, MaxDelegateMsg)
		}
	}
	for _, k := range keysOf(has) {
		if has[k] && !slices.Contains(may, k) {
			return fmt.Errorf("%s: takes no %s", name, k)
		}
	}
	return nil
}

// validateFrame checks the item's frame, or piece, and its id.
func (d DelegateItem) validateFrame(name string) error {
	if !carriesFrame(d.Step) {
		if len(d.Frame) > 0 || d.ID != nil || d.Off > 0 || d.Size > 0 || d.Seq > 0 {
			return fmt.Errorf("%s: carries no frame", name)
		}
		return nil
	}
	switch {
	case len(d.Frame) > 0 && len(d.ID) != 16:
		return fmt.Errorf("%s: a frame's id is 16 bytes", name)
	case len(d.Frame) == 0 && (d.ID != nil || d.Size > 0):
		return fmt.Errorf("%s: an id or a size without a frame", name)
	case d.Seq > 0 && d.Step != DelegateFrame:
		return fmt.Errorf("%s: only a connection's frame has a seq", name)
	case d.Size == 0 && d.Off > 0:
		return fmt.Errorf("%s: an offset is a piece's, with its size", name)
	case d.Size > MaxDelegateFrame, d.Size == 0 && len(d.Frame) > MaxDelegateFrame:
		return fmt.Errorf("%s: a frame is %d bytes at most", name, MaxDelegateFrame)
	case d.Size > 0 && d.Off+uint64(len(d.Frame)) > d.Size:
		return fmt.Errorf("%s: a piece past its frame's size", name)
	}
	return nil
}

// ReadDelegate reads a delegate item as fromDelegate's, and checks it. The
// item has its Task, Step and N whenever they read, so a receiver answers
// one about what it does not have with a close (Answerable) rather than
// with an err.
func ReadDelegate(raw cbor.RawMessage, fromDelegate bool) (DelegateItem, error) {
	var head struct {
		N    uint64 `cbor:"1,keyasint"`
		Task []byte `cbor:"15,keyasint"`
		Step int    `cbor:"16,keyasint"`
	}
	_ = UnmarshalCBOR(raw, &head)
	part := DelegateItem{T: ItemDelegate, N: head.N, Task: head.Task, Step: head.Step}
	var d DelegateItem
	if err := UnmarshalCBOR(raw, &d); err != nil {
		return part, fmt.Errorf("delegate: %w", err)
	}
	return d, d.Validate(fromDelegate)
}

// Pieces is d as items whose frames take at most room bytes each: d itself
// when its frame fits, else pieces of it, each with its Off and the
// whole's Size, the rest of d's keys on every piece. A room under 1 takes
// a byte a piece.
func (d DelegateItem) Pieces(room int) []DelegateItem {
	if len(d.Frame) <= room || d.Size > 0 {
		return []DelegateItem{d}
	}
	room = max(room, 1)
	var out []DelegateItem
	for off := 0; off < len(d.Frame); off += room {
		p := d
		p.Frame = d.Frame[off:min(off+room, len(d.Frame))]
		p.Off, p.Size = uint64(off), uint64(len(d.Frame))
		out = append(out, p)
	}
	return out
}

// DelegateJoiner puts the frames that come in pieces together, one for
// each (step, n, seq) the pieces name. A piece sent again is taken once by
// its offset, pieces may come in any order and overlap, and what never
// completes is dropped after a while (Expire), since a lost frame is not
// sent again.
type DelegateJoiner struct {
	// MaxHeld is the most bytes of frames being joined it holds at once
	// (0: 4 MiB); a piece of a new frame past it is refused.
	MaxHeld int

	joining map[joinKey]*joining
	held    int
}

type joinKey struct {
	step   int
	n, seq uint64
}

type joining struct {
	buf   []byte
	spans [][2]uint64 // the bytes it has, sorted and apart
	since time.Time
}

// ErrDelegateHeld: a piece of a frame past what a joiner holds at once.
var ErrDelegateHeld = errors.New("delegate: too many frames in pieces at once")

// Add takes an item: its frame whole when it is not in pieces, or when this
// piece completes it (done); nothing yet otherwise. A piece that disagrees
// with the size its frame's first said is refused.
func (j *DelegateJoiner) Add(d DelegateItem, now time.Time) (frame []byte, done bool, err error) {
	if !d.Pieced() {
		return d.Frame, true, nil
	}
	if j.joining == nil {
		j.joining = map[joinKey]*joining{}
	}
	key := joinKey{d.Step, d.N, d.Seq}
	f, ok := j.joining[key]
	if !ok {
		limit := j.MaxHeld
		if limit <= 0 {
			limit = 4 << 20
		}
		if j.held+int(d.Size) > limit {
			return nil, false, ErrDelegateHeld
		}
		f = &joining{buf: make([]byte, d.Size), since: now}
		j.joining[key] = f
		j.held += int(d.Size)
	}
	if uint64(len(f.buf)) != d.Size {
		return nil, false, fmt.Errorf("delegate: a piece says size %d, its frame %d", d.Size, len(f.buf))
	}
	copy(f.buf[d.Off:], d.Frame)
	f.spans = addSpan(f.spans, [2]uint64{d.Off, d.Off + uint64(len(d.Frame))})
	if len(f.spans) == 1 && f.spans[0] == [2]uint64{0, d.Size} {
		delete(j.joining, key)
		j.held -= len(f.buf)
		return f.buf, true, nil
	}
	return nil, false, nil
}

// Drop forgets what is being joined for n (an exchange answered, a
// connection closed).
func (j *DelegateJoiner) Drop(n uint64) {
	for k, f := range j.joining {
		if k.n == n {
			delete(j.joining, k)
			j.held -= len(f.buf)
		}
	}
}

// Expire forgets frames whose first piece came before before: the rest
// was lost on the way, and is never sent again.
func (j *DelegateJoiner) Expire(before time.Time) {
	for k, f := range j.joining {
		if f.since.Before(before) {
			delete(j.joining, k)
			j.held -= len(f.buf)
		}
	}
}

// Held is how many bytes of frames being joined it holds.
func (j *DelegateJoiner) Held() int { return j.held }

// addSpan adds s to spans, sorted and apart, merging what touches.
func addSpan(spans [][2]uint64, s [2]uint64) [][2]uint64 {
	if s[0] >= s[1] {
		return spans
	}
	spans = append(spans, s)
	sort.Slice(spans, func(a, b int) bool { return spans[a][0] < spans[b][0] })
	out := spans[:1]
	for _, x := range spans[1:] {
		last := &out[len(out)-1]
		if x[0] <= last[1] {
			last[1] = max(last[1], x[1])
			continue
		}
		out = append(out, x)
	}
	return out
}

// Serving, in a build schema: a delegate command's Serves are the channel
// kinds its minions serve, the channel's side of each transport.

// validateServes checks a command's Serves: only a delegate command's, and
// one's required; each a channel kind once, of the kinds its action
// serves (bind kinds for a delegate, reverse ones for a reverse
// delegate), MaxServes at most.
func validateServes(c BuildCommand) error {
	if !IsDelegateAction(c.Action) {
		if len(c.Serves) > 0 {
			return fmt.Errorf("serves: only a delegate command (%s) says what it serves", strings.Join(DelegateActions(), ", "))
		}
		return nil
	}
	if len(c.Serves) == 0 {
		return fmt.Errorf("serves: a %s command serves at least one channel kind", c.Action)
	}
	if len(c.Serves) > MaxServes {
		return fmt.Errorf("serves: %d at most", MaxServes)
	}
	bind := c.Action == ActionDelegate
	for i, s := range c.Serves {
		if err := validateChannelVersions(s); err != nil {
			return fmt.Errorf("serves %q: %w", s.ModuleName, err)
		}
		if len(s.Kinds) == 0 {
			return fmt.Errorf("serves %q: at least one connection kind", s.ModuleName)
		}
		for _, k := range s.Kinds {
			if IsBindKind(k) != bind {
				return fmt.Errorf("serves %q: a %s command serves %s kinds, not %s", s.ModuleName, c.Action, map[bool]string{true: "bind", false: "reverse"}[bind], k)
			}
		}
		for _, prev := range c.Serves[:i] {
			if prev.ModuleName == s.ModuleName {
				return fmt.Errorf("serves: duplicate %q", s.ModuleName)
			}
		}
	}
	if len(c.Kinds) == 0 || slices.Contains(c.Kinds, KindBindCall) {
		return fmt.Errorf("kinds: a %s command names the kinds it works over, never %s: a page runs no task between calls", c.Action, KindBindCall)
	}
	return nil
}

// Serving is the place, from 1, of the first of c's Serves that serves
// moduleName's kind at version; 0 when none does.
func (c BuildCommand) Serving(moduleName, kind string, version int) int {
	for i, s := range c.Serves {
		if s.ModuleName == moduleName && slices.Contains(s.Kinds, kind) && slices.Contains(s.Versions, version) {
			return i + 1
		}
	}
	return 0
}

// Served is c's Serves entry at place (from 1), as a step's Serve names it.
func (c BuildCommand) Served(place uint64) (ChannelVersions, bool) {
	if place < 1 || place > uint64(len(c.Serves)) {
		return ChannelVersions{}, false
	}
	return c.Serves[place-1], true
}
