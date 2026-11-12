package protocol

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// A minion's config (docs: contracts/minion-build.md, The minion config): a
// build's settings as a minion reads them, for a factory that asks for them so
// (BuildSchema.MinionConfig). Core makes it with each build request
// (BuildRequest.MinionConfig) as numbered CBOR, as core's messages are: a
// convenience, the settings of the JSON beside it numbered with the schemas
// only core holds together. What goes into a minion is the factory's to
// decide: it may bake the bytes in whole (its minion then reads them with
// ReadMinionConfig, by numbers alone), take parts of them, or leave them.
// The channels and their connection parameters, the build's fields and
// the connection kinds go by number (BuildChannel.Num, FieldSpec.Num,
// KindNumber); the types here carry CBOR tags alone, so none of their
// names reaches a minion.

// MaxMinionConfigSize bounds a minion config.
const MaxMinionConfigSize = 1 << 16

// MaxFieldNumber bounds a field's number (FieldSpec.Num) and a channel's
// in a build schema (BuildChannel.Num), as MaxCommandNumber does a
// command's.
const MaxFieldNumber = MaxCommandNumber

// The connection kinds' numbers in a minion config (MinionConnection.Kind).
const (
	KindNumReverseCall       uint64 = 1
	KindNumReversePersistent uint64 = 2
	KindNumBindCall          uint64 = 3
	KindNumBindPersistent    uint64 = 4
)

var kindNumbers = map[string]uint64{
	KindReverseCall: KindNumReverseCall, KindReversePersistent: KindNumReversePersistent,
	KindBindCall: KindNumBindCall, KindBindPersistent: KindNumBindPersistent,
}

// KindNumber is a connection kind's number (KindNumReverseCall, ...); 0
// for one that is no connection kind.
func KindNumber(kind string) uint64 { return kindNumbers[kind] }

// KindOfNumber is the connection kind numbered n, if there is one.
func KindOfNumber(n uint64) (string, bool) {
	for k, v := range kindNumbers {
		if v == n {
			return k, true
		}
	}
	return "", false
}

// MinionConfig is a build's settings, numbered, as a minion reads them.
type MinionConfig struct {
	// Build is the build's id, 16 bytes: the minion's on the data plane.
	Build []byte `cbor:"1,keyasint"`
	// Crypto is the build's payload crypto suite and the minion's keys;
	// nil for a target whose builds have no suite.
	Crypto *MinionCrypto `cbor:"2,keyasint,omitempty"`
	// Envelope is how the minion writes its messages (EnvelopeJSON, or the
	// factory's own); "" for EnvelopeCBOR.
	Envelope string `cbor:"3,keyasint,omitempty"`
	// Connections are the build's, in the order the minion tries them.
	Connections []MinionConnection `cbor:"4,keyasint"`
	// Failover is the build's failover policy (BuildRequest.Failover).
	Failover *MinionFailover `cbor:"5,keyasint,omitempty"`
	// Ops are the numbers of the commands the minion is built with
	// (BuildCommand.Op), in the schema's order: it has these and no others.
	Ops []uint64 `cbor:"6,keyasint,omitempty"`
	// MaxTasks is how many tasks the minion runs at once as it starts; nil
	// when its factory declares no max_tasks (BuildRequest.MaxTasks).
	MaxTasks *uint64 `cbor:"7,keyasint,omitempty"`
	// Compression is the alg the minion packs items with (PackDeflate); 0
	// for none (BuildRequest.Compression).
	Compression uint64 `cbor:"8,keyasint,omitempty"`
	// Session is the persisted session the minion claims in its hello
	// (HelloItem.SID), 16 bytes; nil for none.
	Session []byte `cbor:"9,keyasint,omitempty"`
	// Values are the build's values of its numbered fields (FieldSpec.Num),
	// by number, each in its type's CBOR form as a task's args are, and
	// read as they are (ArgString, ArgDuration, ArgCredential, ...): a
	// credential field's value is its Credential, in place of the id.
	Values Args `cbor:"10,keyasint,omitempty"`
}

// MinionCrypto is a build's payload crypto suite, by name, and the minion's
// keys: EncKey and MACKey for CryptoAES256CBCHMACSHA256, Material for a
// suite of the factory's own (what the factory made for the build).
type MinionCrypto struct {
	Suite    string `cbor:"1,keyasint"`
	EncKey   []byte `cbor:"2,keyasint,omitempty"`
	MACKey   []byte `cbor:"3,keyasint,omitempty"`
	Material []byte `cbor:"4,keyasint,omitempty"`
}

// Keys is the material of CryptoAES256CBCHMACSHA256.
func (c MinionCrypto) Keys() AES256CBCHMACSHA256Material {
	return AES256CBCHMACSHA256Material{EncKey: c.EncKey, MACKey: c.MACKey}
}

// MinionConnection is one of a build's connections (BuildConnection).
type MinionConnection struct {
	// Channel is the channel's number in the factory's schema
	// (BuildChannel.Num).
	Channel uint64 `cbor:"1,keyasint"`
	// Version is the channel's connection schema version the endpoint
	// follows (ConnectionSchema.Version).
	Version uint64 `cbor:"2,keyasint"`
	// Kind is the connection kind's number (KindNumber).
	Kind uint64 `cbor:"3,keyasint"`
	// Params are the endpoint's: the channel's fields of the kind, by their
	// numbers, defaults filled in.
	Params Args `cbor:"4,keyasint,omitempty"`
	// Values are the factory's connection parameters for it, by their
	// numbers.
	Values Args `cbor:"5,keyasint,omitempty"`
	// Failover is the connection's own failover settings; nil for none.
	Failover *MinionConnectionFailover `cbor:"6,keyasint,omitempty"`
	// MaxMessage is the largest message the connection carries; 0 for
	// MaxMinionMessageSize (BuildConnection.MaxMessage).
	MaxMessage uint64 `cbor:"7,keyasint,omitempty"`
}

// MessageLimit is the largest message the connection carries.
func (c MinionConnection) MessageLimit() int {
	if c.MaxMessage > MaxMinionMessageSize {
		return MaxMinionMessageSize
	}
	return messageLimit(int(c.MaxMessage))
}

// FailoverAuto reports whether failover may move a minion to c, as
// BuildConnection.FailoverAuto does.
func (c MinionConnection) FailoverAuto() bool {
	if c.Failover != nil && c.Failover.Auto != nil {
		return *c.Failover.Auto
	}
	return c.Kind != KindNumBindPersistent
}

// FailAfter is how many failures in a row move a minion off c under f, as
// BuildConnection.FailAfter is.
func (c MinionConnection) FailAfter(f MinionFailover) uint64 {
	if c.Failover != nil && c.Failover.FailAfter > 0 {
		return c.Failover.FailAfter
	}
	return f.FailAfter
}

// MinionFailover is a build's failover policy (BuildFailover), its
// durations in milliseconds.
type MinionFailover struct {
	Enabled       bool   `cbor:"1,keyasint,omitempty"`
	FailAfter     uint64 `cbor:"2,keyasint,omitempty"`
	FailFor       uint64 `cbor:"3,keyasint,omitempty"`
	Wrap          bool   `cbor:"4,keyasint,omitempty"`
	CyclePause    uint64 `cbor:"5,keyasint,omitempty"`
	FailbackAfter uint64 `cbor:"6,keyasint,omitempty"`
}

// DefaultMinionFailover is DefaultBuildFailover as a minion config carries
// it: what a minion falls back to when its config has no policy.
func DefaultMinionFailover() MinionFailover {
	return MinionFailover{Enabled: true, FailAfter: 5, Wrap: true, CyclePause: 5 * 60 * 1000, FailbackAfter: 60 * 60 * 1000}
}

// Minion is the policy as a minion config carries it.
func (f BuildFailover) Minion() MinionFailover {
	failFor, pause, back := f.Durations()
	return MinionFailover{
		Enabled: f.Enabled, FailAfter: uint64(max(f.FailAfter, 0)), FailFor: millis(failFor), Wrap: f.Wrap,
		CyclePause: millis(pause), FailbackAfter: millis(back),
	}
}

// Durations are the policy's durations.
func (f MinionFailover) Durations() (failFor, cyclePause, failbackAfter time.Duration) {
	ms := func(n uint64) time.Duration { return time.Duration(n) * time.Millisecond }
	return ms(f.FailFor), ms(f.CyclePause), ms(f.FailbackAfter)
}

// MinionConnectionFailover is a connection's own failover settings
// (ConnectionFailover).
type MinionConnectionFailover struct {
	Auto      *bool  `cbor:"1,keyasint,omitempty"`
	FailAfter uint64 `cbor:"2,keyasint,omitempty"`
}

// ConnectionSchemaAt gives a channel's connection schema at a version: the
// one a build's connection follows. False when it is not known.
type ConnectionSchemaAt func(moduleName string, version int) (ConnectionSchema, bool)

// NewMinionConfig is the minion config of r, a build request of s, whose
// connections follow the schemas channel gives. Every channel of r has a
// number in s, and every field of a connection's kind one in its channel's
// schema; the build's fields and the factory's connection parameters go
// in only when numbered. An error says what keeps a config from being made.
func NewMinionConfig(s BuildSchema, r BuildRequest, channel ConnectionSchemaAt) (MinionConfig, error) {
	var c MinionConfig
	t, ok := s.Target(r.Target)
	if !ok {
		return c, fmt.Errorf("target %q is not the factory's", r.Target)
	}
	var err error
	if c.Build, err = uuidBytes(r.BuildID); err != nil {
		return c, fmt.Errorf("build_id: %w", err)
	}
	if r.Crypto != nil {
		if c.Crypto, err = minionCrypto(*r.Crypto); err != nil {
			return c, fmt.Errorf("crypto: %w", err)
		}
	}
	if r.Envelope != EnvelopeCBOR {
		c.Envelope = r.Envelope
	}
	for i, bc := range r.Connections {
		mc, err := minionConnection(s, r, bc, channel)
		if err != nil {
			return c, fmt.Errorf("connections[%d]: %w", i, err)
		}
		c.Connections = append(c.Connections, mc)
	}
	if r.Failover != nil {
		f := r.Failover.Minion()
		c.Failover = &f
	}
	for _, id := range r.Commands {
		i := slices.IndexFunc(s.Commands, func(cmd BuildCommand) bool { return cmd.ID == id })
		if i < 0 {
			return c, fmt.Errorf("command %q is not the factory's", id)
		}
		c.Ops = append(c.Ops, uint64(s.Commands[i].Op))
	}
	c.MaxTasks = r.MaxTasks
	switch r.Compression {
	case "":
	case CompressionDeflate:
		c.Compression = PackDeflate
	default:
		return c, fmt.Errorf("compression %q has no number", r.Compression)
	}
	if r.SessionID != "" {
		if c.Session, err = uuidBytes(r.SessionID); err != nil {
			return c, fmt.Errorf("session_id: %w", err)
		}
	}
	if c.Values, err = numberedValues(s.PlatformFields(t, r.Platform), r.Values, r.Credentials, false); err != nil {
		return c, fmt.Errorf("values.%w", err)
	}
	return c, nil
}

// EncodeMinionConfig is r's minion config (NewMinionConfig), encoded: what
// core puts in BuildRequest.MinionConfig.
func EncodeMinionConfig(s BuildSchema, r BuildRequest, channel ConnectionSchemaAt) ([]byte, error) {
	c, err := NewMinionConfig(s, r, channel)
	if err != nil {
		return nil, err
	}
	return c.Marshal()
}

// minionConfigEnc writes a config the same way every time: core's
// deterministic encoding, maps in the order of their encoded keys.
var minionConfigEnc = func() cbor.EncMode {
	m, err := cbor.EncOptions{
		Sort: cbor.SortCoreDeterministic, ShortestFloat: cbor.ShortestFloat16, IndefLength: cbor.IndefLengthForbidden,
		TagsMd: cbor.TagsForbidden,
	}.EncMode()
	if err != nil {
		panic(err)
	}
	return m
}()

// Marshal encodes c, checked, the same bytes for the same config.
func (c MinionConfig) Marshal() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	b, err := minionConfigEnc.Marshal(c)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxMinionConfigSize {
		return nil, fmt.Errorf("a minion config of %d bytes, %d at most", len(b), MaxMinionConfigSize)
	}
	return b, nil
}

// ReadMinionConfig decodes and checks a minion config.
func ReadMinionConfig(b []byte) (MinionConfig, error) {
	var c MinionConfig
	if len(b) > MaxMinionConfigSize {
		return c, fmt.Errorf("a minion config of %d bytes, %d at most", len(b), MaxMinionConfigSize)
	}
	if err := cborDec.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("a minion config: %w", err)
	}
	if err := c.Validate(); err != nil {
		return c, err
	}
	return c, nil
}

// Validate checks a config's shape: what a minion can rely on in one it
// read. Its errors name no field: a minion links them in.
func (c MinionConfig) Validate() error {
	if len(c.Build) != 16 {
		return errors.New("build: 16 bytes")
	}
	if c.Crypto != nil {
		if err := c.Crypto.validate(); err != nil {
			return fmt.Errorf("crypto: %w", err)
		}
	}
	if c.Envelope == EnvelopeCBOR {
		return errors.New("envelope: none for cbor")
	}
	if len(c.Connections) == 0 {
		return errors.New("connections: at least one")
	}
	for i, mc := range c.Connections {
		if err := mc.validate(); err != nil {
			return fmt.Errorf("connections[%d]: %w", i, err)
		}
	}
	if f := c.Failover; f != nil {
		failFor, pause, back := f.Durations()
		switch {
		case f.FailAfter < 1 || f.FailAfter > MaxFailAfter:
			return fmt.Errorf("failover: 1 to %d failures before a move", MaxFailAfter)
		case failFor > MaxFailFor || pause > MaxCyclePause || back > MaxFailbackAfter:
			return errors.New("failover: a duration past its limit")
		}
	}
	for i, op := range c.Ops {
		if op < 1 || op > MaxCommandNumber {
			return fmt.Errorf("ops: %d is no command's number", op)
		}
		if slices.Contains(c.Ops[:i], op) {
			return fmt.Errorf("ops: %d twice", op)
		}
	}
	if c.MaxTasks != nil && *c.MaxTasks > MaxTasksLimit {
		return fmt.Errorf("max tasks: %d at most", MaxTasksLimit)
	}
	if c.Compression != 0 && c.Compression != PackDeflate {
		return fmt.Errorf("compression: alg %d is none of the protocol's", c.Compression)
	}
	if c.Session != nil && len(c.Session) != 16 {
		return errors.New("session: 16 bytes")
	}
	return checkNumbered("values", c.Values)
}

func (c MinionCrypto) validate() error {
	switch {
	case c.Suite == "":
		return errors.New("a suite")
	case slices.Contains(CoreSuites, c.Suite):
		if len(c.EncKey) != 32 || len(c.MACKey) != 32 || c.Material != nil {
			return fmt.Errorf("%s: two 32-byte keys", c.Suite)
		}
	case c.EncKey != nil || c.MACKey != nil || len(c.Material) == 0 || len(c.Material) > MaxCodecKeySize:
		return fmt.Errorf("%s: its material, 1 to %d bytes", c.Suite, MaxCodecKeySize)
	}
	return nil
}

func (c MinionConnection) validate() error {
	if c.Channel < 1 || c.Channel > MaxFieldNumber {
		return errors.New("channel: a channel's number")
	}
	if c.Version < 1 {
		return errors.New("version: at least 1")
	}
	if _, ok := KindOfNumber(c.Kind); !ok {
		return fmt.Errorf("kind: %d is no connection kind", c.Kind)
	}
	if c.MaxMessage != 0 && (c.MaxMessage < MinConnectionMessage || c.MaxMessage > MaxMinionMessageSize) {
		return fmt.Errorf("message limit: %d to %d bytes", MinConnectionMessage, MaxMinionMessageSize)
	}
	if c.Failover != nil && c.Failover.FailAfter > MaxFailAfter {
		return fmt.Errorf("failover: %d failures at most", MaxFailAfter)
	}
	if err := checkNumbered("params", c.Params); err != nil {
		return err
	}
	return checkNumbered("values", c.Values)
}

// checkNumbered checks a config's numbered values: each by a field's
// number.
func checkNumbered(name string, values Args) error {
	for n := range values {
		if n < 1 || n > MaxFieldNumber {
			return fmt.Errorf("%s: %d is no field's number", name, n)
		}
	}
	return nil
}

// minionConnection is c, a connection of r, numbered.
func minionConnection(s BuildSchema, r BuildRequest, c BuildConnection, channel ConnectionSchemaAt) (MinionConnection, error) {
	var mc MinionConnection
	e := c.Endpoint
	bc, ok := s.Channel(e.Channel.ModuleName)
	if !ok {
		return mc, fmt.Errorf("channel %q is not the factory's", e.Channel.ModuleName)
	}
	if bc.Num == 0 {
		return mc, fmt.Errorf("channel %q has no number in the factory's schema", e.Channel.ModuleName)
	}
	kind := c.ConnectionKind()
	if mc.Kind = KindNumber(kind); mc.Kind == 0 {
		return mc, fmt.Errorf("kind %q is no connection kind", kind)
	}
	cs, ok := channel(e.Channel.ModuleName, e.Channel.SchemaVersion)
	if !ok {
		return mc, fmt.Errorf("channel %q's connection schema version %d is not known", e.Channel.ModuleName, e.Channel.SchemaVersion)
	}
	fields := cs.KindFields(kind)
	if !cs.Numbered(kind) {
		return mc, fmt.Errorf("channel %q numbers no fields of its %s connections: a minion reads them by number", e.Channel.ModuleName, kind)
	}
	mc.Channel, mc.Version = uint64(bc.Num), uint64(max(e.Channel.SchemaVersion, 0))
	var err error
	if mc.Params, err = numberedValues(fields, e.Params, r.Credentials, true); err != nil {
		return mc, fmt.Errorf("params.%w", err)
	}
	if mc.Values, err = numberedValues(bc.KindFields(kind), c.Values, r.Credentials, false); err != nil {
		return mc, fmt.Errorf("values.%w", err)
	}
	if f := c.Failover; f != nil {
		mc.Failover = &MinionConnectionFailover{Auto: f.Auto, FailAfter: uint64(max(f.FailAfter, 0))}
	}
	mc.MaxMessage = uint64(max(c.MaxMessage, 0))
	return mc, nil
}

// numberedValues are values of fields by the fields' numbers, each in its
// type's CBOR form (as a task's args, credentials in place of their ids):
// all of them (every field numbered, as a channel's must be), or the
// numbered ones alone (a schema stored before numbers were required). A
// file field and a field with no value are left out; an error names the
// field ("<key>: ...").
func numberedValues(fields []FieldSpec, values map[string]any, given map[string]Credential, all bool) (Args, error) {
	var out Args
	for _, f := range fields {
		if f.Type == FieldFile {
			continue // its bytes are the factory's to handle
		}
		if f.Num == 0 {
			if all {
				return nil, fmt.Errorf("%s: no number", f.Key)
			}
			continue
		}
		v, ok := values[f.Key]
		if !ok || v == nil {
			continue
		}
		cv, err := configValue(f, v, given)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.Key, err)
		}
		if cv == nil {
			continue
		}
		if out == nil {
			out = Args{}
		}
		out[uint64(f.Num)] = cv
	}
	return out, nil
}

// configValue is v, field f's value, in its type's CBOR form: a credential
// field's the credential it names (a credential_list's, the list), from
// those the request gives.
func configValue(f FieldSpec, v any, given map[string]Credential) (any, error) {
	if isCredentialField(f.Type) {
		creds, err := FieldCredentials(f, v, given)
		if err != nil {
			return nil, err
		}
		if f.Type == FieldCredentialList {
			return creds, nil
		}
		if len(creds) == 0 {
			return nil, nil
		}
		return creds[0], nil
	}
	return taskArg(f, v)
}

// minionCrypto is a request's crypto with its material as bytes: core's
// suite's two keys, or a factory suite's own material.
func minionCrypto(c BuildCrypto) (*MinionCrypto, error) {
	out := &MinionCrypto{Suite: c.Suite}
	if slices.Contains(CoreSuites, c.Suite) {
		var m AES256CBCHMACSHA256Material
		if err := json.Unmarshal(c.Material, &m); err != nil {
			return nil, fmt.Errorf("%s's material: %w", c.Suite, err)
		}
		out.EncKey, out.MACKey = m.EncKey, m.MACKey
		return out, nil
	}
	if err := json.Unmarshal(c.Material, &out.Material); err != nil {
		return nil, fmt.Errorf("%s's material: %w", c.Suite, err)
	}
	return out, nil
}

// uuidBytes is a lowercase UUID's 16 bytes.
func uuidBytes(id string) ([]byte, error) {
	if !buildIDPattern.MatchString(id) {
		return nil, fmt.Errorf("%q is not a lowercase UUIDv4", id)
	}
	return hex.DecodeString(strings.ReplaceAll(id, "-", ""))
}

// millis is d in whole milliseconds, 0 for a negative one.
func millis(d time.Duration) uint64 {
	if d < 0 {
		return 0
	}
	return uint64(d / time.Millisecond)
}
