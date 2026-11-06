package protocol

import (
	"errors"
	"fmt"
	"unicode/utf8"
)

// Identity (docs: contracts/minion-messages/identity): who a
// minion's work runs as, when that is not its process's own. The hello's
// user, domain and integrity are the process's own, and only that; a rehello
// says when the process itself changed (an in-process setuid). An identity
// says who the tasks run as instead: the session's tasks from now on (a
// thread token, network-only credentials, a become), or one task's. Any
// minion may send it, on every connection kind, in its next message: before
// it acks a task that runs under it. Core answers nothing; one sent again
// changes nothing, as core keeps one identity for the session and one per
// task.

// IdentityItem is who the session's tasks, or a task, run as (minion →
// core).
type IdentityItem struct {
	T int `cbor:"0,keyasint"`
	// Scope is IdentitySession (the tasks the minion acks after it, until
	// the next) or IdentityTask (Task alone, whatever the session's).
	Scope int `cbor:"1,keyasint"`
	// Task is the task it is for (IdentityTask), or the task that made it
	// (IdentitySession: a become, a steal_token), 16 bytes; nil when no
	// task did.
	Task []byte `cbor:"2,keyasint,omitempty"`
	// User is as the OS writes it ("CORP\\admin", "root"), Domain the
	// Windows domain when apart. Both empty for the process's own.
	User   string `cbor:"3,keyasint,omitempty"`
	Domain string `cbor:"4,keyasint,omitempty"`
	// Integrity is one of the Integrity levels, as the hello's: 0 when the
	// minion does not say.
	Integrity int `cbor:"5,keyasint,omitempty"`
	// How is one of the Identity ways (IdentityImpersonation, ...); 0 is
	// the process's own: for the session, back to it (a rev2self, an
	// unbecome); for a task, that it runs as the process whatever the
	// session's identity (an agentless channel's file commands, say). A
	// way this version does not know is taken, shown by its number.
	How int `cbor:"6,keyasint,omitempty"`
	// Credential is the id of the credential it took, when one of a task's
	// credentials made it (a make_token's password, a become's), the
	// minion naming it only once it was used and accepted: core marks it
	// valid. It needs Task, the task that gave it.
	Credential string `cbor:"7,keyasint,omitempty"`
}

// Identity scopes.
const (
	// IdentitySession: the session's tasks from now on.
	IdentitySession = 1
	// IdentityTask: one task, whatever the session's.
	IdentityTask = 2
)

// Identity ways: how the work comes to run as User.
const (
	// IdentityImpersonation: a thread token (an impersonated or a made
	// one): the work runs locally as User.
	IdentityImpersonation = 1
	// IdentityNetwork: network-only credentials: locally the process's
	// own, on the network User.
	IdentityNetwork = 2
	// IdentityBecome: the work is started as User (sudo, su).
	IdentityBecome = 3
)

// MaxIdentityText bounds an identity's user and domain.
const MaxIdentityText = 256

var identityHowNames = map[int]string{
	IdentityImpersonation: "impersonation", IdentityNetwork: "network", IdentityBecome: "become",
}

// IdentityHowName is a way's name: "" for the process's own, "how 7" for one
// this version does not know.
func IdentityHowName(how int) string {
	if how == 0 {
		return ""
	}
	if n, ok := identityHowNames[how]; ok {
		return n
	}
	return fmt.Sprintf("how %d", how)
}

// Validate checks the item: a scope, a task where it needs one, and a user
// with any way (none for the process's own).
func (i IdentityItem) Validate() error {
	switch {
	case i.Scope != IdentitySession && i.Scope != IdentityTask:
		return errors.New("identity: scope is 1 (the session's tasks) or 2 (one task)")
	case i.Task != nil && len(i.Task) != 16:
		return errors.New("identity: task is 16 bytes")
	case i.Scope == IdentityTask && i.Task == nil:
		return errors.New("identity: one task's names the task")
	case i.How < 0:
		return errors.New("identity: how is 0 (the process's own) or a way")
	case i.How == 0 && (i.User != "" || i.Domain != "" || i.Integrity != 0 || i.Credential != ""):
		return errors.New("identity: the process's own says no user, domain, integrity or credential")
	case i.How != 0 && i.User == "":
		return errors.New("identity: a way names its user")
	case len(i.User) > MaxIdentityText || len(i.Domain) > MaxIdentityText:
		return fmt.Errorf("identity: user and domain are %d bytes at most", MaxIdentityText)
	case !utf8.ValidString(i.User) || !utf8.ValidString(i.Domain):
		return errors.New("identity: user and domain are UTF-8")
	case i.Integrity < 0:
		return errors.New("identity: integrity is a level")
	case i.Credential != "" && i.Task == nil:
		return errors.New("identity: a credential is a task's: name the task")
	case len(i.Credential) > MaxCredentialIDLength:
		return fmt.Errorf("identity: a credential id is %d bytes at most", MaxCredentialIDLength)
	}
	return nil
}

// Own: the item says the process's own identity (no way).
func (i IdentityItem) Own() bool { return i.How == 0 }
