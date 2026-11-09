package protocol

import (
	"bytes"
	"errors"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestDelegateRegistry(t *testing.T) {
	id := bytes.Repeat([]byte{1}, 16)
	d := DelegateItem{T: ItemDelegate, N: 1, Values: map[string]any{"k": "v"}, ID: id, Frame: id, Deadline: 1, Status: 200,
		Failure: &LinkFailure{Kind: LinkFailOther}, Head: id, Peer: []byte{10, 0, 0, 1}, Under: id,
		Credentials: map[string]Credential{"c": {ID: "c", Type: "password"}}, Logins: []LinkLogin{{Credential: "c"}},
		Task: id, Step: DelegateAnswer, Serve: 1, Seq: 1, Off: 1, Size: 20, Reason: 1, Msg: "m"}
	b, err := MarshalCBOR(d)
	if err != nil {
		t.Fatal(err)
	}
	// Keys 1 to 13 are the control link's, for the same things; 11 and 14
	// (keys, acting) are an agentless kind's, never here.
	want := []uint64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 13, 15, 16, 17, 18, 19, 20, 21, 22}
	if got := keysOfCBOR(t, b); !slices.Equal(got, want) {
		t.Fatalf("keys %v, want %v", got, want)
	}
	if ItemType(b) != 29 || ItemName(ItemDelegate) != "delegate" {
		t.Fatalf("type %d %q", ItemType(b), ItemName(ItemDelegate))
	}
	for name, got := range map[string][]int{
		"steps":  {DelegateSync, DelegateReply, DelegateCall, DelegateOpen, DelegateAnswer, DelegateFrame, DelegateClose},
		"closes": {DelegateClosed, DelegateNoConnection, DelegateTaskEnded},
	} {
		for i, n := range got {
			if n != i+1 {
				t.Errorf("%s: %v, want 1, 2, 3…", name, got)
			}
		}
	}
	if DelegateStepName(DelegateOpen) != "open" || DelegateStepName(9) != "step 9" ||
		DelegateCloseName(DelegateTaskEnded) != "task_ended" || DelegateCloseName(9) != "reason 9" {
		t.Fatal("names")
	}
}

func TestDelegateValidate(t *testing.T) {
	task, id := bytes.Repeat([]byte{7}, 16), bytes.Repeat([]byte{1}, 16)
	sync := func() DelegateItem {
		return DelegateItem{T: ItemDelegate, Task: task, Step: DelegateSync, N: 1, Serve: 1, ID: id, Frame: []byte{1, 2}}
	}
	ok := []struct {
		name string
		from bool
		d    DelegateItem
	}{
		{"a sync", true, sync()},
		{"a sync with its peer", true, func() DelegateItem { d := sync(); d.Peer = []byte{10, 0, 0, 5}; return d }()},
		{"a reply", false, DelegateItem{Task: task, Step: DelegateReply, N: 1, Status: ReplyOK, ID: id, Frame: []byte{1}}},
		{"a reply of nothing", false, DelegateItem{Task: task, Step: DelegateReply, N: 1, Status: ReplyNoContent}},
		{"a refusal", false, DelegateItem{Task: task, Step: DelegateReply, N: 1, Status: 422}},
		{"a call", false, DelegateItem{Task: task, Step: DelegateCall, N: 1, Serve: 1, Values: map[string]any{"url": "u"},
			ID: id, Frame: []byte{1}, Deadline: 1000}},
		{"an open", false, DelegateItem{Task: task, Step: DelegateOpen, N: 1, Serve: 2, Values: map[string]any{}, Deadline: 1000,
			Under: id}},
		{"an answer that opened", true, DelegateItem{Task: task, Step: DelegateAnswer, N: 1, Peer: []byte{10, 0, 0, 5}}},
		{"an answer with a frame", true, DelegateItem{Task: task, Step: DelegateAnswer, N: 1, ID: id, Frame: []byte{1}, Status: 200}},
		{"an answer that is not the minion", true, DelegateItem{Task: task, Step: DelegateAnswer, N: 1, Status: 404, Head: []byte("x")}},
		{"a failed answer", true, DelegateItem{Task: task, Step: DelegateAnswer, N: 1,
			Failure: &LinkFailure{Kind: LinkFailUnreachable, Msg: "refused"}}},
		{"a frame from core", false, DelegateItem{Task: task, Step: DelegateFrame, N: 3, Seq: 2, ID: id, Frame: []byte{1}}},
		{"a reverse connection's first frame", true, DelegateItem{Task: task, Step: DelegateFrame, N: 3, Serve: 1,
			Peer: []byte{10, 0, 0, 5}, ID: id, Frame: []byte{1}}},
		{"a piece", true, DelegateItem{Task: task, Step: DelegateFrame, N: 3, ID: id, Frame: []byte{1, 2}, Off: 4, Size: 6}},
		{"a close", true, DelegateItem{Task: task, Step: DelegateClose, N: 3, Reason: DelegateClosed, Msg: "eof"}},
	}
	for _, c := range ok {
		if err := c.d.Validate(c.from); err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	bad := []struct {
		want string
		from bool
		d    DelegateItem
	}{
		{"task is 16 bytes", true, DelegateItem{Task: id[:3], Step: DelegateSync, N: 1}},
		{"n is from 1", true, func() DelegateItem { d := sync(); d.N = 0; return d }()},
		{"step 9 is not one this version knows", true, DelegateItem{Task: task, Step: 9, N: 1}},
		{"a delegate does not send it", true, DelegateItem{Task: task, Step: DelegateCall, N: 1}},
		{"core does not send it", false, sync()},
		{"serve is from 1", true, func() DelegateItem { d := sync(); d.Serve = 0; return d }()},
		{"takes no deadline", true, func() DelegateItem { d := sync(); d.Deadline = 5; return d }()},
		{"a frame's id is 16 bytes", true, func() DelegateItem { d := sync(); d.ID = nil; return d }()},
		{"peer is 4 bytes or 16", true, func() DelegateItem { d := sync(); d.Peer = []byte{1}; return d }()},
		{"200 carries a frame", false, DelegateItem{Task: task, Step: DelegateReply, N: 1, Status: 200}},
		{"only 200 carries a frame", false, DelegateItem{Task: task, Step: DelegateReply, N: 1, Status: 204, ID: id, Frame: []byte{1}}},
		{"status is the sync call's", false, DelegateItem{Task: task, Step: DelegateReply, N: 1}},
		{"a deadline is required", false, DelegateItem{Task: task, Step: DelegateCall, N: 1, Serve: 1, ID: id, Frame: []byte{1}}},
		{"open: carries no frame", false, DelegateItem{Task: task, Step: DelegateOpen, N: 1, Serve: 1, Deadline: 1, ID: id, Frame: []byte{1}}},
		{"under is 16 bytes", false, DelegateItem{Task: task, Step: DelegateOpen, N: 1, Serve: 1, Deadline: 1, Under: id[:2]}},
		{"call: takes no under", false, DelegateItem{Task: task, Step: DelegateCall, N: 1, Serve: 1, Deadline: 1, Under: id}},
		{"a failure carries no frame", true, DelegateItem{Task: task, Step: DelegateAnswer, N: 1, ID: id, Frame: []byte{1},
			Failure: &LinkFailure{Kind: 1}}},
		{"a failure has a kind", true, DelegateItem{Task: task, Step: DelegateAnswer, N: 1, Failure: &LinkFailure{}}},
		{"a head is for what is not a minion message", true, DelegateItem{Task: task, Step: DelegateAnswer, N: 1, ID: id,
			Frame: []byte{1}, Head: []byte("x")}},
		{"head longer than 512", true, DelegateItem{Task: task, Step: DelegateAnswer, N: 1, Head: make([]byte, 513)}},
		{"a frame is required", false, DelegateItem{Task: task, Step: DelegateFrame, N: 1}},
		{"frame: takes no serve", false, DelegateItem{Task: task, Step: DelegateFrame, N: 1, Serve: 1, ID: id, Frame: []byte{1}}},
		{"reason is 1 (closed) or more", true, DelegateItem{Task: task, Step: DelegateClose, N: 1}},
		{"carries no frame", true, DelegateItem{Task: task, Step: DelegateClose, N: 1, Reason: 1, ID: id, Frame: []byte{1}}},
		{"msg longer than 256", true, DelegateItem{Task: task, Step: DelegateClose, N: 1, Reason: 1, Msg: strings.Repeat("m", 257)}},
		{"only a connection's frame has a seq", true, func() DelegateItem { d := sync(); d.Seq = 1; return d }()},
		{"an offset is a piece's", true, func() DelegateItem { d := sync(); d.Off = 1; return d }()},
		{"a piece past its frame's size", true, func() DelegateItem { d := sync(); d.Off, d.Size = 1, 2; return d }()},
		{"a frame is 1048576 bytes at most", true, func() DelegateItem { d := sync(); d.Size = MaxDelegateFrame + 1; return d }()},
	}
	for _, c := range bad {
		err := c.d.Validate(c.from)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("want %q, got %v", c.want, err)
		}
	}
}

func TestReadDelegate(t *testing.T) {
	task := bytes.Repeat([]byte{7}, 16)
	b, _ := MarshalCBOR(DelegateItem{T: ItemDelegate, Task: task, Step: DelegateFrame, N: 4})
	d, err := ReadDelegate(b, true)
	if err == nil || !strings.Contains(err.Error(), "a frame is required") {
		t.Fatalf("err %v", err)
	}
	if !d.Answerable() || d.N != 4 || d.Step != DelegateFrame {
		t.Fatalf("the item's head reads, to answer it: %+v", d)
	}
	if d, err := ReadDelegate([]byte{0xff}, true); err == nil || d.Answerable() {
		t.Fatalf("not CBOR: %+v %v", d, err)
	}
}

func TestDelegatePiecesJoin(t *testing.T) {
	task, id := bytes.Repeat([]byte{7}, 16), bytes.Repeat([]byte{1}, 16)
	frame := make([]byte, 10_000)
	for i := range frame {
		frame[i] = byte(i * 7)
	}
	d := DelegateItem{T: ItemDelegate, Task: task, Step: DelegateFrame, N: 2, Seq: 5, ID: id, Frame: frame}
	if got := d.Pieces(len(frame)); len(got) != 1 || got[0].Pieced() {
		t.Fatal("a frame that fits goes whole")
	}
	pieces := d.Pieces(999)
	if len(pieces) != 11 {
		t.Fatalf("%d pieces", len(pieces))
	}
	for _, p := range pieces {
		if err := p.Validate(false); err != nil {
			t.Fatal(err)
		}
	}
	// Out of order, some twice, and some again as another split would cut
	// them (the sender's room changed): the frame joins once.
	again := d.Pieces(3001)
	all := append(append(slices.Clone(pieces), pieces[3], pieces[0]), again[1:]...)
	rng := rand.New(rand.NewPCG(1, 2))
	rng.Shuffle(len(all), func(i, j int) { all[i], all[j] = all[j], all[i] })
	var j DelegateJoiner
	now := time.Unix(1000, 0)
	joined := 0
	for _, p := range all {
		got, done, err := j.Add(p, now)
		if err != nil {
			t.Fatal(err)
		}
		if done {
			joined++
			if !bytes.Equal(got, frame) {
				t.Fatal("joined wrong")
			}
		}
	}
	// After it is whole, pieces of it start over: a sender's piece sent
	// again opens a new join that never completes, and expires.
	if joined < 1 {
		t.Fatal("never joined")
	}
	j.Expire(now.Add(time.Second))
	if j.Held() != 0 {
		t.Fatalf("held %d", j.Held())
	}
	// A whole frame passes at once.
	if got, done, _ := j.Add(DelegateItem{Frame: []byte{9}}, now); !done || !bytes.Equal(got, []byte{9}) {
		t.Fatal("whole")
	}
	// A piece whose size disagrees with its frame's, and too much held.
	_, _, _ = j.Add(pieces[0], now)
	odd := pieces[1]
	odd.Size++
	if _, _, err := j.Add(odd, now); err == nil {
		t.Fatal("size mismatch taken")
	}
	j.Drop(d.N)
	if j.Held() != 0 {
		t.Fatal("drop")
	}
	small := DelegateJoiner{MaxHeld: 15_000}
	if _, _, err := small.Add(pieces[0], now); err != nil {
		t.Fatal(err)
	}
	other := pieces[0]
	other.Seq = 6
	if _, _, err := small.Add(other, now); !errors.Is(err, ErrDelegateHeld) {
		t.Fatalf("held: %v", err)
	}
}

func TestBuildSchemaServes(t *testing.T) {
	serving := func(action string, kinds []string, serves ...ChannelVersions) BuildSchema {
		s := exampleBuildSchema(t)
		s.Commands = append(s.Commands, BuildCommand{ID: "serve", Op: 40, Action: action, Kinds: kinds, Serves: serves,
			Params: []FieldSpec{{Key: "listen", Num: 1, Type: FieldString, Required: true}}})
		return s
	}
	bind := ChannelVersions{ModuleName: "tcp", Versions: []int{1}, Kinds: []string{KindBindPersistent, KindBindCall}}
	rev := ChannelVersions{ModuleName: "http", Versions: []int{3}, Kinds: []string{KindReverseCall}}
	s := serving(ActionReverseDelegate, []string{KindReverseCall}, rev)
	if err := ValidateBuildSchema(s); err != nil {
		t.Fatalf("a reverse delegate: its params need no default (an operator starts it): %v", err)
	}
	c, _ := s.Command("serve")
	if c.Serving("http", KindReverseCall, 3) != 1 || c.Serving("http", KindReverseCall, 2) != 0 || c.Serving("tcp", KindBindCall, 1) != 0 {
		t.Fatal("serving")
	}
	if v, ok := c.Served(1); !ok || v.ModuleName != "http" {
		t.Fatal("served")
	}
	if _, ok := c.Served(2); ok {
		t.Fatal("served 2")
	}
	if !HoldsNoSlot(ActionDelegate) || !HoldsNoSlot(ActionTunnel) || HoldsNoSlot(ActionListDir) {
		t.Fatal("slots")
	}
	if !IsCoreParam(ActionDelegate, ParamStopIdle) || !IsCoreParam(ActionReverseDelegate, ParamStopIdle) {
		t.Fatal("stop_idle is core's")
	}
	for _, c := range []struct {
		want   string
		schema BuildSchema
	}{
		{`param "listen" needs a default`, serving(ActionDelegate, []string{KindReverseCall}, bind)},
		{"serves: a delegate command serves at least one", func() BuildSchema {
			s := serving(ActionDelegate, []string{KindReverseCall})
			s.Commands[len(s.Commands)-1].Params[0].Default = "x"
			return s
		}()},
		{`serves "http": a delegate command serves bind kinds, not reverse-call`, func() BuildSchema {
			s := serving(ActionDelegate, []string{KindReverseCall}, rev)
			s.Commands[len(s.Commands)-1].Params[0].Default = "x"
			return s
		}()},
		{`serves "tcp": a reverse_delegate command serves reverse kinds`, serving(ActionReverseDelegate, []string{KindReverseCall}, bind)},
		{`serves: duplicate "http"`, serving(ActionReverseDelegate, []string{KindReverseCall}, rev, rev)},
		{`serves "http": at least one connection kind`, serving(ActionReverseDelegate, []string{KindReverseCall},
			ChannelVersions{ModuleName: "http", Versions: []int{3}})},
		{"kinds: a reverse_delegate command names the kinds it works over, never bind-call", serving(ActionReverseDelegate, nil, rev)},
		{"serves: only a delegate command", func() BuildSchema {
			s := exampleBuildSchema(t)
			s.Commands[2].Serves = []ChannelVersions{rev}
			return s
		}()},
		{`param "stop_idle" is core's`, func() BuildSchema {
			s := serving(ActionReverseDelegate, []string{KindReverseCall}, rev)
			s.Commands[len(s.Commands)-1].Params = append(s.Commands[len(s.Commands)-1].Params,
				FieldSpec{Key: ParamStopIdle, Num: 2, Type: FieldDuration, Default: "1h"})
			return s
		}()},
	} {
		err := ValidateBuildSchema(c.schema)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("want %q, got %v", c.want, err)
		}
	}
}

func TestConnectionDelegatedOnly(t *testing.T) {
	s := validConnection()
	k := s.Kinds[KindBindCall]
	k.DelegatedOnly = true
	s.Kinds[KindBindCall] = k
	if err := ValidateConnectionSchema(s); err != nil || !s.IsDelegatedOnly(KindBindCall) || s.IsDelegatedOnly(KindReverseCall) {
		t.Fatalf("delegated only: %v", err)
	}
	k.Agentless = true
	s.Kinds[KindBindCall] = k
	if err := ValidateConnectionSchema(s); err == nil || !strings.Contains(err.Error(), "an agentless kind is not delegated") {
		t.Fatalf("agentless and delegated only: %v", err)
	}
}
