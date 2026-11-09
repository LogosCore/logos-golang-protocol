package protocol

import (
	"errors"
	"fmt"
	"slices"
	"unicode/utf8"
)

// The factory link (docs: contracts/minion-messages/codecs/, The factory
// link): a WebSocket each instance of a translating factory
// (BuildSchema.Translates) keeps open to core, beside its control-plane
// session, as a channel keeps its control link (link.go). Core sends a
// call, one per message each way, or one for keys; the factory runs the
// layers of the build's codec that are its own and answers by the call's
// request id, in any order. Each binary frame is one CBOR map: a
// FactoryCall core → factory, a FactoryAnswer factory → core. Liveness is
// the control link's: pings every 30 seconds, a socket silent for 90
// dropped; the factory opens it again, backing off.

// FactoryLinkPath is core's endpoint for the factory link, under core's
// base URL: a WebSocket handshake with HeaderFactoryInstance. An instance
// not registered, dead or blocked gets 403.
const FactoryLinkPath = "/api/factory/link"

// HeaderFactoryInstance names the factory instance opening a factory link:
// its registered instance id.
const HeaderFactoryInstance = "Logos-Factory-Instance"

// Factory link frames, by their key 0.
const (
	// FactoryInbound (core → factory): a minion's message to read. Data is
	// the payload as the channel gave it (the factory's suite), or the
	// plaintext core opened (its envelope alone); the answer's Data is the
	// message in CBOR, or the plaintext for core's envelope.
	FactoryInbound = 1
	// FactoryOutbound (core → factory): a message for a minion to write.
	// Data is the message in CBOR (the factory's envelope), or the
	// plaintext core's envelope wrote (its suite alone); the answer's Data
	// is the payload, or the plaintext its envelope wrote, which core
	// seals.
	FactoryOutbound = 2
	// FactoryAnswer (factory → core): the answer to a call.
	FactoryAnswer = 3
	// FactoryKeys (core → factory): make keys of the factory's suite, for
	// a build (FactoryKeysForBuild) or a stage (FactoryKeysForStage).
	FactoryKeys = 4
)

// What a FactoryKeys call makes keys for (FactoryCall.For).
const (
	// FactoryKeysForBuild: a build's keys, before core sends the build
	// request. The answer's Material goes in its crypto.
	FactoryKeysForBuild = 1
	// FactoryKeysForStage: a stage's keys. StageKey is the stage item's
	// key; the answer's Material is kept under the temporary id and its
	// Wrapped goes in the stage_response's keys.
	FactoryKeysForStage = 2
)

// Kinds of CodecFailure: why a call has no result.
const (
	// CodecFailNotOpened: no key fits, or a check failed.
	CodecFailNotOpened = 1
	// CodecFailNotMessage: it opened, and does not decode.
	CodecFailNotMessage = 2
	// CodecFailRefused: a stage key the suite does not take, or a suite
	// without staging.
	CodecFailRefused = 3
	// CodecFailOther: anything else.
	CodecFailOther = 4
)

var codecFailNames = map[int]string{
	CodecFailNotOpened: "not_opened", CodecFailNotMessage: "not_message", CodecFailRefused: "refused",
	CodecFailOther: "other",
}

// CodecFailName is a failure kind's name, for people.
func CodecFailName(kind int) string {
	if n, ok := codecFailNames[kind]; ok {
		return n
	}
	return fmt.Sprintf("failure %d", kind)
}

// MaxFactoryFrameSize bounds a factory link frame: the message limit grown
// by the most a codec may declare, plus 64 KiB for the keys and the rest.
const MaxFactoryFrameSize = MaxMinionMessageSize*MaxCodecGrowth/100 + MaxCodecOverhead + 64<<10

// FactoryCall is a frame core → factory: FactoryInbound, FactoryOutbound
// or FactoryKeys.
//
// Every call carries Request (core's, unique among its calls waiting on
// that link), Build (the build's id, 16 bytes) and Deadline
// (milliseconds: the call's timeout, BuildCodec.CallTimeout).
//
// An inbound or outbound call carries ID (the id the message is sent
// under, 16 bytes), Data, and Layers: the layers of the build's codec that
// are the factory's (Codec.Layers), [CodecLayerSuite],
// [CodecLayerEnvelope] or both. With the suite among them it carries Keys:
// inbound, the candidate key materials in order (the id's own, then a
// persisted session's replaced keys, newest first), at most
// MaxCodecCandidates; outbound, the one material of the id.
//
// A keys call carries For, and for a stage StageKey: the stage item's key.
type FactoryCall struct {
	Type     int      `cbor:"0,keyasint"`
	Request  uint64   `cbor:"1,keyasint"`
	Build    []byte   `cbor:"2,keyasint"`
	ID       []byte   `cbor:"3,keyasint,omitempty"`
	Data     []byte   `cbor:"4,keyasint,omitempty"`
	Deadline uint64   `cbor:"5,keyasint"`
	Keys     [][]byte `cbor:"6,keyasint,omitempty"`
	Layers   []int    `cbor:"7,keyasint,omitempty"`
	For      int      `cbor:"8,keyasint,omitempty"`
	StageKey []byte   `cbor:"9,keyasint,omitempty"`
}

// Suite reports whether the call's layers include the factory's suite.
func (c FactoryCall) Suite() bool { return slices.Contains(c.Layers, CodecLayerSuite) }

// Envelope reports whether the call's layers include the factory's
// envelope.
func (c FactoryCall) Envelope() bool { return slices.Contains(c.Layers, CodecLayerEnvelope) }

// Validate checks a call's keys against its type.
func (c FactoryCall) Validate() error {
	switch {
	case c.Request == 0:
		return errors.New("factory call: request is 1 or more")
	case len(c.Build) != 16:
		return errors.New("factory call: the build is 16 bytes")
	case c.Deadline == 0:
		return errors.New("factory call: a deadline")
	}
	switch c.Type {
	case FactoryInbound, FactoryOutbound:
		name := map[int]string{FactoryInbound: "inbound", FactoryOutbound: "outbound"}[c.Type]
		switch {
		case len(c.ID) != 16:
			return fmt.Errorf("factory %s: the id is 16 bytes", name)
		case len(c.Data) == 0:
			return fmt.Errorf("factory %s: no bytes", name)
		case !slices.Equal(c.Layers, []int{CodecLayerSuite}) && !slices.Equal(c.Layers, []int{CodecLayerEnvelope}) &&
			!slices.Equal(c.Layers, []int{CodecLayerSuite, CodecLayerEnvelope}):
			return fmt.Errorf("factory %s: layers are [1], [2] or [1, 2]", name)
		case c.For != 0 || c.StageKey != nil:
			return fmt.Errorf("factory %s: for and the stage key are a keys call's", name)
		case !c.Suite() && c.Keys != nil:
			return fmt.Errorf("factory %s: keys are the factory's suite's", name)
		case c.Suite() && c.Type == FactoryInbound && (len(c.Keys) == 0 || len(c.Keys) > MaxCodecCandidates):
			return fmt.Errorf("factory inbound: 1 to %d keys", MaxCodecCandidates)
		case c.Suite() && c.Type == FactoryOutbound && len(c.Keys) != 1:
			return errors.New("factory outbound: the one key of the id")
		}
		for i, k := range c.Keys {
			if len(k) == 0 || len(k) > MaxCodecKeySize {
				return fmt.Errorf("factory %s: key %d is 1 to %d bytes", name, i, MaxCodecKeySize)
			}
		}
	case FactoryKeys:
		switch {
		case c.ID != nil || c.Data != nil || c.Keys != nil || c.Layers != nil:
			return errors.New("factory keys: only request, build, deadline, for and the stage key")
		case c.For != FactoryKeysForBuild && c.For != FactoryKeysForStage:
			return fmt.Errorf("factory keys: for is %d (a build) or %d (a stage)", FactoryKeysForBuild, FactoryKeysForStage)
		case c.For == FactoryKeysForBuild && c.StageKey != nil:
			return errors.New("factory keys: a stage key is a stage's")
		case c.For == FactoryKeysForStage && (len(c.StageKey) == 0 || len(c.StageKey) > MaxCodecKeySize):
			return fmt.Errorf("factory keys: a stage's key is 1 to %d bytes", MaxCodecKeySize)
		}
	default:
		return fmt.Errorf("factory call: type %d", c.Type)
	}
	return nil
}

// FactoryAnswerFrame is a frame factory → core (FactoryAnswer): Request,
// then a result or a Failure.
//
// The result of an inbound or outbound call is Data, and of an inbound
// one through the factory's suite Opened too: the index in the call's Keys
// of the material that opened it, so core tells a replaced holder
// session_replaced. The result of a keys call is Material, and for a stage
// Wrapped: the material wrapped for the stage's key, which core puts in
// the stage_response.
type FactoryAnswerFrame struct {
	Type     int           `cbor:"0,keyasint"`
	Request  uint64        `cbor:"1,keyasint"`
	Data     []byte        `cbor:"2,keyasint,omitempty"`
	Opened   *uint64       `cbor:"3,keyasint,omitempty"`
	Failure  *CodecFailure `cbor:"4,keyasint,omitempty"`
	Material []byte        `cbor:"10,keyasint,omitempty"`
	Wrapped  []byte        `cbor:"11,keyasint,omitempty"`
}

// CodecFailure is why a call has no result: Kind (CodecFailNotOpened,
// ...) and a message for people.
type CodecFailure struct {
	Kind int    `cbor:"1,keyasint"`
	Msg  string `cbor:"2,keyasint,omitempty"`
}

// Validate checks an answer on its own: a result or a failure, and their
// sizes. ValidateFor checks it against the call it answers.
func (a FactoryAnswerFrame) Validate() error {
	result := a.Data != nil || a.Material != nil
	switch {
	case a.Type != FactoryAnswer:
		return fmt.Errorf("factory answer: type %d", a.Type)
	case a.Request == 0:
		return errors.New("factory answer: request is 1 or more")
	case result == (a.Failure != nil):
		return errors.New("factory answer: a result or a failure, one of them")
	case a.Data != nil && a.Material != nil:
		return errors.New("factory answer: bytes or keys, one of them")
	case a.Data != nil && len(a.Data) == 0:
		return errors.New("factory answer: no bytes")
	case a.Opened != nil && a.Data == nil:
		return errors.New("factory answer: opened goes with the bytes")
	case a.Wrapped != nil && a.Material == nil:
		return errors.New("factory answer: the wrapped material goes with the material")
	case a.Material != nil && (len(a.Material) == 0 || len(a.Material) > MaxCodecKeySize):
		return fmt.Errorf("factory answer: the material is 1 to %d bytes", MaxCodecKeySize)
	case a.Wrapped != nil && (len(a.Wrapped) == 0 || len(a.Wrapped) > MaxCodecKeySize):
		return fmt.Errorf("factory answer: the wrapped material is 1 to %d bytes", MaxCodecKeySize)
	}
	if f := a.Failure; f != nil {
		if _, ok := codecFailNames[f.Kind]; !ok {
			return fmt.Errorf("factory answer: failure kind %d", f.Kind)
		}
		if len(f.Msg) > MaxLinkFailureMsg || !utf8.ValidString(f.Msg) {
			return fmt.Errorf("factory answer: a failure's message is UTF-8, %d bytes at most", MaxLinkFailureMsg)
		}
	}
	return nil
}

// ValidateFor checks an answer against the call it answers: the result
// that call takes, Opened within its keys, and an inbound message within
// the protocol's limit. A failure answers any call.
func (a FactoryAnswerFrame) ValidateFor(c FactoryCall) error {
	if err := a.Validate(); err != nil {
		return err
	}
	if a.Request != c.Request {
		return fmt.Errorf("factory answer: request %d answers %d", a.Request, c.Request)
	}
	if a.Failure != nil {
		return nil
	}
	switch c.Type {
	case FactoryInbound:
		switch {
		case a.Data == nil:
			return errors.New("factory answer: an inbound call's result is the message")
		case len(a.Data) > MaxMinionMessageSize:
			return fmt.Errorf("factory answer: a message of %d bytes is over %d", len(a.Data), MaxMinionMessageSize)
		case c.Suite() && a.Opened == nil:
			return errors.New("factory answer: which key opened it")
		case c.Suite() && *a.Opened >= uint64(len(c.Keys)):
			return fmt.Errorf("factory answer: opened %d of %d keys", *a.Opened, len(c.Keys))
		case !c.Suite() && a.Opened != nil:
			return errors.New("factory answer: opened is the factory's suite's")
		}
	case FactoryOutbound:
		switch {
		case a.Data == nil:
			return errors.New("factory answer: an outbound call's result is the bytes")
		case a.Opened != nil:
			return errors.New("factory answer: opened is an inbound call's")
		}
	case FactoryKeys:
		switch {
		case a.Material == nil:
			return errors.New("factory answer: a keys call's result is the material")
		case c.For == FactoryKeysForStage && a.Wrapped == nil:
			return errors.New("factory answer: a stage's keys are wrapped for its key")
		case c.For == FactoryKeysForBuild && a.Wrapped != nil:
			return errors.New("factory answer: a build's keys are not wrapped")
		}
	}
	return nil
}

// EncodeFactoryCall encodes a call core sends.
func EncodeFactoryCall(c FactoryCall) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return encodeFactoryFrame(c)
}

// DecodeFactoryCall decodes and checks a call, as a factory reads it.
func DecodeFactoryCall(b []byte) (FactoryCall, error) {
	var c FactoryCall
	if err := decodeFactoryFrame(b, &c); err != nil {
		return FactoryCall{}, err
	}
	return c, c.Validate()
}

// EncodeFactoryAnswer encodes an answer a factory sends.
func EncodeFactoryAnswer(a FactoryAnswerFrame) ([]byte, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}
	return encodeFactoryFrame(a)
}

// DecodeFactoryAnswer decodes and checks an answer, as core reads it;
// ValidateFor checks it against its call.
func DecodeFactoryAnswer(b []byte) (FactoryAnswerFrame, error) {
	var a FactoryAnswerFrame
	if err := decodeFactoryFrame(b, &a); err != nil {
		return FactoryAnswerFrame{}, err
	}
	return a, a.Validate()
}

func encodeFactoryFrame(v any) ([]byte, error) {
	b, err := cborEnc.Marshal(v)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxFactoryFrameSize {
		return nil, fmt.Errorf("factory link frame of %d bytes is over %d", len(b), MaxFactoryFrameSize)
	}
	return b, nil
}

func decodeFactoryFrame(b []byte, v any) error {
	if len(b) > MaxFactoryFrameSize {
		return fmt.Errorf("factory link frame of %d bytes is over %d", len(b), MaxFactoryFrameSize)
	}
	if err := cborDec.Unmarshal(b, v); err != nil {
		return fmt.Errorf("factory link frame: %w", err)
	}
	return nil
}
