package protocol

import (
	"errors"
	"fmt"
	"net/netip"
	"unicode/utf8"
)

// The control link (docs: contracts/channel-core-connections/, The control
// link and connection sockets: formats): a WebSocket each channel instance
// opens to core, over which core asks the channel to reach bind minions.
// Core sends a call; the channel delivers the sealed message to the target
// and answers with what came back, by the request's id. Each binary frame is
// one LinkFrame. On an agentless kind (ConnectionKind.Agentless) the channel
// is the minion: it answers the message itself.

// LinkPath is core's endpoint for the control link, under core's base URL:
// a WebSocket handshake with HeaderChannelInstance.
const LinkPath = "/api/channel/link"

// Link frames, by LinkFrame.Type.
const (
	// LinkCall (core → channel): deliver Data, sent under ID, to the target
	// Values say, and answer with what came back.
	LinkCall = 1
	// LinkOpen (core → channel): open a bind-persistent connection to the
	// target Values say: the channel dials, then opens the connection's
	// socket naming the request (HeaderOpenRequest), or answers with a
	// failure. Under says the id the minion speaks under on it.
	LinkOpen = 2
	// LinkAnswer (channel → core): the answer to request Request.
	LinkAnswer = 3
)

// Kinds of LinkFailure: why a call reached nothing.
const (
	// LinkFailUnreachable: no connection (DNS, refused, no route).
	LinkFailUnreachable = 1
	// LinkFailTimeout: no answer within the deadline.
	LinkFailTimeout = 2
	// LinkFailTLS: the TLS handshake or the certificate failed.
	LinkFailTLS = 3
	// LinkFailOther: anything else (the target's values do not make a
	// request, a proxy failed, the channel draining).
	LinkFailOther = 4
	// LinkFailLogin: the target refused the login the channel was given;
	// the message says why, and what the target offers. Retrying changes
	// nothing until the target is edited.
	LinkFailLogin = 5
	// LinkFailHostKey: the target is not the one the target's values say
	// (its host key, or its certificate, is not the one given); the message
	// says what it presented.
	LinkFailHostKey = 6
)

var linkFailNames = map[int]string{
	LinkFailUnreachable: "unreachable", LinkFailTimeout: "timeout", LinkFailTLS: "tls", LinkFailOther: "other",
	LinkFailLogin: "login", LinkFailHostKey: "host_key",
}

// LinkFailName is a failure kind's name, for people.
func LinkFailName(kind int) string {
	if n, ok := linkFailNames[kind]; ok {
		return n
	}
	return fmt.Sprintf("failure %d", kind)
}

// Limits of a link frame.
const (
	// MaxLinkLogins bounds an answer's logins.
	MaxLinkLogins = MaxCredentialListItems
	// MaxLinkFrameSize bounds a link frame: a minion message's sealed frame
	// with the values and room to spare.
	MaxLinkFrameSize = MaxMinionMessageSize + 128<<10
	// MaxLinkExcerpt bounds what an answer quotes of a response that is not
	// a minion message.
	MaxLinkExcerpt = 512
	// MaxLinkFailureMsg bounds a failure's message.
	MaxLinkFailureMsg = 512
)

// LinkFrame is one frame of the control link.
//
// A call carries Request, Values (the build connection's built-in values
// and the target's, by the keys the channel declared for the kind), ID (the
// id the message is sent under, 16 bytes), Data (the sealed message) and
// Deadline (milliseconds, optional: the channel keeps to the shorter of it
// and its own timeout). To an agentless kind (ConnectionKind.Agentless) it
// carries Keys too: the keys of ID, which the channel acting as the minion
// opens the message and seals its answer with.
//
// A call and an open carry Credentials too, when the values name any: the
// credentials of the endpoint's and the target's credential fields
// (FieldCredential), by id, as the values name them by id. The answer may
// carry Logins: how each credential the channel tried fared, so core can
// say which worked (an agentless channel logging in to a server).
//
// A call and an open to an agentless kind carry Acting too, when the
// session they go under has an identity a task made (a become): that task,
// its command and args as its task item carried them (credentials in place
// of ids, resolved when the task was queued), so a channel that keeps
// nothing between calls takes it up again on every connection, as a minion
// would keep it. None for any other kind.
//
// An open carries Request, Values, Deadline and Under: the id the minion
// speaks under on the new connection, 16 bytes, its target's open session's
// id, else its build's. The minion speaks first, as on any persistent
// connection; one that keeps no ids of its own (a channel acting as it)
// takes them from Under, and a channel whose minion knows its ids ignores
// it. A key of its own, so a channel from before it decodes the frame. To an
// agentless kind it carries Keys too: the keys of Under.
//
// An answer carries Request and one of:
//   - ID and Data: what came back was a minion message in the channel's
//     transport format, unpacked: the id it is sent under and its sealed
//     frame, which core opens. Status is the transport's (the HTTP status).
//   - Failure: nothing came back.
//   - neither: something answered that is not a minion message (an HTTP
//     404, a WAF's page): Status, and Excerpt, the start of what came back.
//
// An answer that reached something may carry Peer: the IP address the
// channel connected to (the minion's external address, as a reverse
// channel's Logos-Peer-Address is), when the channel knows it without a
// lookup of its own: dialed directly, or the target an IP address. Empty
// for a host name a proxy resolved.
type LinkFrame struct {
	Type     int            `cbor:"0,keyasint"`
	Request  uint64         `cbor:"1,keyasint"`
	Values   map[string]any `cbor:"2,keyasint,omitempty"`
	ID       []byte         `cbor:"3,keyasint,omitempty"`
	Data     []byte         `cbor:"4,keyasint,omitempty"`
	Deadline uint64         `cbor:"5,keyasint,omitempty"`
	Status   int            `cbor:"6,keyasint,omitempty"`
	Failure  *LinkFailure   `cbor:"7,keyasint,omitempty"`
	Excerpt  []byte         `cbor:"8,keyasint,omitempty"`
	Peer     string         `cbor:"9,keyasint,omitempty"`
	Under    []byte         `cbor:"10,keyasint,omitempty"`
	Keys     *LinkKeys      `cbor:"11,keyasint,omitempty"`
	// Credentials and Logins: keys of their own, so a channel from before
	// them decodes the frame.
	Credentials map[string]Credential `cbor:"12,keyasint,omitempty"`
	Logins      []LinkLogin           `cbor:"13,keyasint,omitempty"`
	Acting      *LinkActing           `cbor:"14,keyasint,omitempty"`
}

// LinkActing is the task whose identity is in effect for the session a
// call or an open goes under (IdentityItem, scope session, its task): its
// id, command and args, as a task item carries them.
type LinkActing struct {
	Task []byte `cbor:"1,keyasint"`
	Cmd  uint64 `cbor:"2,keyasint"`
	Args Args   `cbor:"3,keyasint,omitempty"`
}

// Validate checks the task's id and command.
func (a LinkActing) Validate() error {
	switch {
	case len(a.Task) != 16:
		return errors.New("acting: the task is 16 bytes")
	case a.Cmd == 0:
		return errors.New("acting: a command")
	}
	return nil
}

// LinkLogin is how one of a call's or an open's credentials fared at the
// target, in the order the channel tried them: Accepted when it logged in,
// else refused. A credential the channel never got to (one before it logged
// in) is not listed.
type LinkLogin struct {
	Credential string `cbor:"1,keyasint"`
	Accepted   bool   `cbor:"2,keyasint,omitempty"`
}

// LinkKeys are the keys of the id a call's or an open's messages go under
// (its build's, its session's), for a channel that acts as the minion
// (ConnectionKind.Agentless): Suite, the build's, and its Material. Core
// sends them with every call and open, as such a channel keeps nothing.
type LinkKeys struct {
	Suite    string                      `cbor:"1,keyasint"`
	Material AES256CBCHMACSHA256Material `cbor:"2,keyasint"`
}

// Validate checks the suite is one the protocol has and its keys' sizes.
func (k LinkKeys) Validate() error {
	if k.Suite != CryptoAES256CBCHMACSHA256 {
		return fmt.Errorf("link keys: suite %q", k.Suite)
	}
	if len(k.Material.EncKey) != 32 || len(k.Material.MACKey) != 32 {
		return errors.New("link keys: two 32-byte keys")
	}
	return nil
}

// LinkFailure is why a call reached nothing: Kind (LinkFailUnreachable,
// ...) and a message for people.
type LinkFailure struct {
	Kind int    `cbor:"1,keyasint"`
	Msg  string `cbor:"2,keyasint,omitempty"`
}

// EncodeLinkFrame encodes a control link frame.
func EncodeLinkFrame(f LinkFrame) ([]byte, error) {
	if err := f.Validate(); err != nil {
		return nil, err
	}
	b, err := cborEnc.Marshal(f)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxLinkFrameSize {
		return nil, fmt.Errorf("link frame of %d bytes is over %d", len(b), MaxLinkFrameSize)
	}
	return b, nil
}

// DecodeLinkFrame decodes and checks a control link frame.
func DecodeLinkFrame(b []byte) (LinkFrame, error) {
	var f LinkFrame
	if len(b) > MaxLinkFrameSize {
		return f, fmt.Errorf("link frame of %d bytes is over %d", len(b), MaxLinkFrameSize)
	}
	if err := cborDec.Unmarshal(b, &f); err != nil {
		return LinkFrame{}, fmt.Errorf("link frame: %w", err)
	}
	return f, f.Validate()
}

// Validate checks a frame's keys against its type.
func (f LinkFrame) Validate() error {
	if f.Request == 0 {
		return errors.New("link frame: request is 1 or more")
	}
	switch f.Type {
	case LinkCall:
		switch {
		case len(f.ID) != 16:
			return errors.New("link call: the id is 16 bytes")
		case len(f.Data) == 0:
			return errors.New("link call: no message")
		case f.Status != 0 || f.Failure != nil || f.Excerpt != nil || f.Peer != "":
			return errors.New("link call: an answer's keys")
		case f.Under != nil:
			return errors.New("link call: under is an open's")
		case f.Keys != nil && f.Keys.Validate() != nil:
			return f.Keys.Validate()
		case f.Logins != nil:
			return errors.New("link call: logins are an answer's")
		case f.Acting != nil && f.Keys == nil:
			return errors.New("link call: acting is an agentless kind's, with keys")
		case f.Acting != nil && f.Acting.Validate() != nil:
			return fmt.Errorf("link call: %w", f.Acting.Validate())
		}
		if err := validateGivenCredentials(f.Credentials); err != nil {
			return fmt.Errorf("link call: %w", err)
		}
	case LinkOpen:
		switch {
		case f.ID != nil || f.Data != nil || f.Status != 0 || f.Failure != nil || f.Excerpt != nil || f.Peer != "":
			return errors.New("link open: only request, values, deadline and under")
		case f.Under != nil && len(f.Under) != 16:
			return errors.New("link open: under is 16 bytes")
		case f.Keys != nil && f.Keys.Validate() != nil:
			return f.Keys.Validate()
		case f.Keys != nil && f.Under == nil:
			return errors.New("link open: keys are under's")
		case f.Logins != nil:
			return errors.New("link open: logins are an answer's")
		case f.Acting != nil && f.Keys == nil:
			return errors.New("link open: acting is an agentless kind's, with keys")
		case f.Acting != nil && f.Acting.Validate() != nil:
			return fmt.Errorf("link open: %w", f.Acting.Validate())
		}
		if err := validateGivenCredentials(f.Credentials); err != nil {
			return fmt.Errorf("link open: %w", err)
		}
	case LinkAnswer:
		switch {
		case f.Values != nil || f.Deadline != 0 || f.Under != nil || f.Keys != nil || f.Credentials != nil || f.Acting != nil:
			return errors.New("link answer: a request's keys")
		case len(f.Logins) > MaxLinkLogins:
			return fmt.Errorf("link answer: %d logins at most", MaxLinkLogins)
		case (f.ID == nil) != (f.Data == nil):
			return errors.New("link answer: id and data come together")
		case f.ID != nil && len(f.ID) != 16:
			return errors.New("link answer: the id is 16 bytes")
		case f.ID != nil && (f.Failure != nil || f.Excerpt != nil):
			return errors.New("link answer: a message, a failure or an excerpt, one of them")
		case f.Failure != nil && (f.Excerpt != nil || f.Status != 0):
			return errors.New("link answer: a failure has no status or excerpt")
		case len(f.Excerpt) > MaxLinkExcerpt:
			return fmt.Errorf("link answer: the excerpt is %d bytes at most", MaxLinkExcerpt)
		case f.Status < 0 || f.Status > 999:
			return errors.New("link answer: status is 0 to 999")
		case f.Peer != "" && f.Failure != nil:
			return errors.New("link answer: a failure reached no peer")
		}
		if f.Peer != "" {
			if _, err := netip.ParseAddr(f.Peer); err != nil {
				return fmt.Errorf("link answer: peer %q is not an IP address", f.Peer)
			}
		}
		for i, l := range f.Logins {
			if l.Credential == "" || len(l.Credential) > MaxCredentialIDLength {
				return fmt.Errorf("link answer: login %d names no credential", i)
			}
		}
		if f.Failure != nil {
			if _, ok := linkFailNames[f.Failure.Kind]; !ok {
				return fmt.Errorf("link answer: failure kind %d", f.Failure.Kind)
			}
			if len(f.Failure.Msg) > MaxLinkFailureMsg || !utf8.ValidString(f.Failure.Msg) {
				return fmt.Errorf("link answer: a failure's message is UTF-8, %d bytes at most", MaxLinkFailureMsg)
			}
		}
	default:
		return fmt.Errorf("link frame: type %d", f.Type)
	}
	return nil
}

// Excerpt is the start of b, at most MaxLinkExcerpt bytes, for an answer.
func Excerpt(b []byte) []byte {
	if len(b) > MaxLinkExcerpt {
		b = b[:MaxLinkExcerpt]
	}
	return append([]byte{}, b...)
}
