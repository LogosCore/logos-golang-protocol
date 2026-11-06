package protocol

import (
	"bytes"
	"strings"
	"testing"
)

// An identity says a scope, names its task where it needs one, and a user
// with any way; the process's own says no one.
func TestIdentityItem(t *testing.T) {
	task := bytes.Repeat([]byte{3}, 16)
	ok := []IdentityItem{
		{T: ItemIdentity, Scope: IdentitySession, Task: task, User: "root", Integrity: IntegrityRoot, How: IdentityBecome, Credential: "c1"},
		{T: ItemIdentity, Scope: IdentitySession, User: `CORP\admin`, Domain: "CORP", Integrity: IntegrityHigh, How: IdentityImpersonation},
		{T: ItemIdentity, Scope: IdentitySession},                             // back to the process's own, no task made it
		{T: ItemIdentity, Scope: IdentitySession, Task: task},                 // an unbecome
		{T: ItemIdentity, Scope: IdentityTask, Task: task},                    // this task runs as the process
		{T: ItemIdentity, Scope: IdentityTask, Task: task, User: "u", How: 9}, // a way a later version has
	}
	for i, it := range ok {
		if err := it.Validate(); err != nil {
			t.Errorf("ok %d: %v", i, err)
		}
	}
	bad := map[string]IdentityItem{
		"no scope":              {T: ItemIdentity, User: "u", How: IdentityBecome},
		"scope 3":               {T: ItemIdentity, Scope: 3},
		"short task":            {T: ItemIdentity, Scope: IdentitySession, Task: []byte{1}},
		"task scope, no task":   {T: ItemIdentity, Scope: IdentityTask, User: "u", How: IdentityBecome},
		"way, no user":          {T: ItemIdentity, Scope: IdentitySession, How: IdentityBecome},
		"own with a user":       {T: ItemIdentity, Scope: IdentitySession, User: "u"},
		"own with a credential": {T: ItemIdentity, Scope: IdentityTask, Task: task, Credential: "c"},
		"credential, no task":   {T: ItemIdentity, Scope: IdentitySession, User: "u", How: IdentityBecome, Credential: "c"},
		"long user":             {T: ItemIdentity, Scope: IdentitySession, User: strings.Repeat("u", MaxIdentityText+1), How: 1},
		"not UTF-8":             {T: ItemIdentity, Scope: IdentitySession, User: "\xff", How: 1},
		"negative integrity":    {T: ItemIdentity, Scope: IdentitySession, User: "u", How: 1, Integrity: -1},
		"negative how":          {T: ItemIdentity, Scope: IdentitySession, How: -1},
		"long credential":       {T: ItemIdentity, Scope: IdentityTask, Task: task, User: "u", How: 1, Credential: strings.Repeat("c", MaxCredentialIDLength+1)},
	}
	for name, it := range bad {
		if err := it.Validate(); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
	for how, want := range map[int]string{0: "", IdentityImpersonation: "impersonation", IdentityNetwork: "network", IdentityBecome: "become", 7: "how 7"} {
		if got := IdentityHowName(how); got != want {
			t.Errorf("IdentityHowName(%d) = %q, want %q", how, got, want)
		}
	}
	if ItemName(ItemIdentity) != "identity" {
		t.Errorf("item 20 is %q", ItemName(ItemIdentity))
	}
}

// A call or an open to an agentless kind may carry the acting task; a frame
// without keys, an answer, or a malformed task may not.
func TestLinkActing(t *testing.T) {
	keys := &LinkKeys{Suite: CryptoAES256CBCHMACSHA256, Material: AES256CBCHMACSHA256Material{EncKey: make([]byte, 32), MACKey: make([]byte, 32)}}
	id, under := bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 16)
	acting := &LinkActing{Task: bytes.Repeat([]byte{4}, 16), Cmd: 10, Args: Args{1: "root"}}
	for _, f := range []LinkFrame{
		{Type: LinkCall, Request: 1, ID: id, Data: []byte{1}, Keys: keys, Acting: acting},
		{Type: LinkOpen, Request: 2, Under: under, Keys: keys, Acting: acting},
	} {
		b, err := EncodeLinkFrame(f)
		if err != nil {
			t.Fatalf("%d: %v", f.Type, err)
		}
		back, err := DecodeLinkFrame(b)
		if err != nil {
			t.Fatal(err)
		}
		if back.Acting == nil || !bytes.Equal(back.Acting.Task, acting.Task) || back.Acting.Cmd != 10 {
			t.Errorf("%d: acting came back as %+v", f.Type, back.Acting)
		}
		if user, _ := ArgString(back.Acting.Args, 1); user != "root" {
			t.Errorf("%d: the args came back as %v", f.Type, back.Acting.Args)
		}
	}
	for name, f := range map[string]LinkFrame{
		"call without keys": {Type: LinkCall, Request: 1, ID: id, Data: []byte{1}, Acting: acting},
		"open without keys": {Type: LinkOpen, Request: 1, Under: under, Acting: acting},
		"answer":            {Type: LinkAnswer, Request: 1, Acting: acting},
		"short task":        {Type: LinkCall, Request: 1, ID: id, Data: []byte{1}, Keys: keys, Acting: &LinkActing{Task: []byte{1}, Cmd: 1}},
		"no command":        {Type: LinkOpen, Request: 1, Under: under, Keys: keys, Acting: &LinkActing{Task: id}},
	} {
		if _, err := EncodeLinkFrame(f); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
}
