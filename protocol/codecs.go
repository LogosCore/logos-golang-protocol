package protocol

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Codecs (docs: contracts/minion-messages/codecs/): a minion message
// becomes bytes in two layers. Its envelope writes the message as
// plaintext (core's: EnvelopeCBOR, EnvelopeJSON); its suite seals the
// plaintext into the payload a channel carries (core's:
// CryptoAES256CBCHMACSHA256). Together they are a build's codec. A factory
// may name a suite or an envelope of its own, "<module_name>.<name>", and
// translate that layer for core over a factory link (factory_link.go).

// Core's envelopes.
const (
	// EnvelopeCBOR is the message in CBOR (the Wire Format page): the
	// default, a build schema or a target that names no envelope.
	EnvelopeCBOR = "cbor"
	// EnvelopeJSON is the message as JSON text, mapped from CBOR one to
	// one (json_envelope.go).
	EnvelopeJSON = "json"
)

// CoreEnvelopes and CoreSuites are the envelopes and suites core
// implements: the names without a dot.
var (
	CoreEnvelopes = []string{EnvelopeCBOR, EnvelopeJSON}
	CoreSuites    = []string{CryptoAES256CBCHMACSHA256}
)

// Codec layers: which of a build's layers its factory translates
// (FactoryCall.Layers), in the order they run on a message core receives.
const (
	CodecLayerSuite    = 1
	CodecLayerEnvelope = 2
)

// Bounds of a codec declaration (BuildCodec) and of what crosses a
// factory link.
const (
	MinCodecGrowth      = 100
	MaxCodecGrowth      = 400
	MaxCodecOverhead    = 4096
	DefaultCodecTimeout = 5 * time.Second
	MinCodecTimeout     = 100 * time.Millisecond
	MaxCodecTimeout     = 30 * time.Second
	// MaxCodecKeySize bounds a factory suite's key material, its wrapped
	// material (a stage_response's keys) and a stage's key.
	MaxCodecKeySize = 4 << 10
	// MaxCodecCandidates bounds the key materials an inbound call carries:
	// the id's own, then a persisted session's replaced keys (the last 4),
	// newest first.
	MaxCodecCandidates = 5
)

// BuildCodec is what a factory declares of the suites and envelopes it
// translates (BuildSchema.Codec): required when the schema or a target
// names a factory's suite or envelope, refused otherwise.
type BuildCodec struct {
	// Growth bounds how much larger than the form core hands it the
	// factory's bytes come back, in percent: MinCodecGrowth to
	// MaxCodecGrowth.
	Growth int `json:"growth"`
	// Overhead is bytes on top of Growth, per message: 0 to
	// MaxCodecOverhead.
	Overhead int `json:"overhead,omitempty"`
	// Timeout is how long a call may take, a Go duration
	// (MinCodecTimeout to MaxCodecTimeout); DefaultCodecTimeout when none.
	Timeout string `json:"timeout,omitempty"`
}

// Validate checks the declaration's bounds.
func (c BuildCodec) Validate() error {
	switch {
	case c.Growth < MinCodecGrowth || c.Growth > MaxCodecGrowth:
		return fmt.Errorf("codec: growth is %d to %d percent", MinCodecGrowth, MaxCodecGrowth)
	case c.Overhead < 0 || c.Overhead > MaxCodecOverhead:
		return fmt.Errorf("codec: overhead is 0 to %d bytes", MaxCodecOverhead)
	}
	_, err := durationLimit("codec: timeout", c.Timeout, MinCodecTimeout, MaxCodecTimeout)
	return err
}

// CallTimeout is how long core waits for one call: the declared timeout,
// or DefaultCodecTimeout.
func (c BuildCodec) CallTimeout() time.Duration {
	if d, err := durationLimit("timeout", c.Timeout, MinCodecTimeout, MaxCodecTimeout); err == nil && d > 0 {
		return d
	}
	return DefaultCodecTimeout
}

// Bound is the most a message of n bytes, in the form core hands the
// factory, may come back as: n × Growth / 100 + Overhead.
func (c BuildCodec) Bound(n int) int {
	return n*c.Growth/100 + c.Overhead
}

// IsFactoryCodec reports whether a suite or envelope name is a factory's:
// it has a dot. Core's names have none.
func IsFactoryCodec(name string) bool { return strings.Contains(name, ".") }

// CodecOwner reports whether name is one of module's own:
// "<module_name>.<name>", with a name after the dot.
func CodecOwner(name, module string) bool {
	rest, ok := strings.CutPrefix(name, module+".")
	return ok && module != "" && rest != ""
}

// Codec is a build's codec: the suite ("" for none) and the envelope it is
// made with.
type Codec struct {
	Suite    string `json:"suite,omitempty"`
	Envelope string `json:"envelope"`
}

// Layers are the layers of c its factory translates: CodecLayerSuite for
// a factory's suite, CodecLayerEnvelope for its envelope, in that order;
// none when c is core's alone.
func (c Codec) Layers() []int {
	var out []int
	if IsFactoryCodec(c.Suite) {
		out = append(out, CodecLayerSuite)
	}
	if IsFactoryCodec(c.Envelope) {
		out = append(out, CodecLayerEnvelope)
	}
	return out
}

// Translated reports whether the factory translates any layer of c.
func (c Codec) Translated() bool { return len(c.Layers()) > 0 }

// Agentless reports whether a channel acting as the minion can speak c:
// core's CBOR envelope and core's suite (or none), what the protocol's
// minion speaks.
func (c Codec) Agentless() bool {
	return c.Envelope == EnvelopeCBOR && !IsFactoryCodec(c.Suite)
}

// TargetCodec is the codec builds of t are made with: the target's suite
// and envelope where it names them, else the schema's, EnvelopeCBOR when
// neither names an envelope.
func (s BuildSchema) TargetCodec(t BuildTarget) Codec {
	c := Codec{Suite: s.Crypto, Envelope: s.Envelope}
	if t.Crypto != "" {
		c.Suite = t.Crypto
	}
	if t.Envelope != "" {
		c.Envelope = t.Envelope
	}
	if c.Envelope == "" {
		c.Envelope = EnvelopeCBOR
	}
	return c
}

// Translates reports whether any of the schema's targets has a layer its
// factory translates: the factory opens a factory link.
func (s BuildSchema) Translates() bool {
	for _, t := range s.Targets {
		if s.TargetCodec(t).Translated() {
			return true
		}
	}
	return false
}

// validateCodecs checks the schema's and its targets' suites and envelopes
// (a name core has, or one in a factory's form) and that the codec
// declaration is there exactly when one of them is a factory's. The owner
// of a factory's names is ValidateCodecOwner's, which needs the module.
func validateCodecs(s BuildSchema) error {
	check := func(where, suite, envelope string) error {
		if suite != "" {
			if !cryptoSuitePattern.MatchString(suite) {
				return fmt.Errorf("%scrypto suite %q must match %s", where, suite, cryptoSuitePattern)
			}
			if !IsFactoryCodec(suite) && !slices.Contains(CoreSuites, suite) {
				return fmt.Errorf("%scrypto suite %q: core's are %s; a factory's own is <module_name>.<name>", where, suite,
					strings.Join(CoreSuites, ", "))
			}
		}
		if envelope != "" {
			if !cryptoSuitePattern.MatchString(envelope) {
				return fmt.Errorf("%senvelope %q must match %s", where, envelope, cryptoSuitePattern)
			}
			if !IsFactoryCodec(envelope) && !slices.Contains(CoreEnvelopes, envelope) {
				return fmt.Errorf("%senvelope %q: core's are %s; a factory's own is <module_name>.<name>", where, envelope,
					strings.Join(CoreEnvelopes, ", "))
			}
		}
		return nil
	}
	if err := check("", s.Crypto, s.Envelope); err != nil {
		return err
	}
	for _, t := range s.Targets {
		if err := check(fmt.Sprintf("target %q: ", t.ID), t.Crypto, t.Envelope); err != nil {
			return err
		}
	}
	names := s.FactoryCodecs()
	switch {
	case len(names) > 0 && s.Codec == nil:
		return fmt.Errorf("codec: required, the factory names its own %s", strings.Join(names, ", "))
	case len(names) == 0 && s.Codec != nil:
		return errors.New("codec: only for a factory that names a suite or an envelope of its own")
	case s.Codec != nil:
		return s.Codec.Validate()
	}
	return nil
}

// FactoryCodecs are the suites and envelopes of the factory's own that
// the schema and its targets name, each once, in the schema's order.
func (s BuildSchema) FactoryCodecs() []string {
	var out []string
	add := func(names ...string) {
		for _, n := range names {
			if IsFactoryCodec(n) && !slices.Contains(out, n) {
				out = append(out, n)
			}
		}
	}
	add(s.Crypto, s.Envelope)
	for _, t := range s.Targets {
		add(t.Crypto, t.Envelope)
	}
	return out
}

// ValidateCodecOwner checks that the suites and envelopes of the factory's
// own that a schema names are module's ("<module>.<name>"): core refuses a
// registration naming another module's.
func ValidateCodecOwner(s BuildSchema, module string) error {
	for _, n := range s.FactoryCodecs() {
		if !CodecOwner(n, module) {
			return fmt.Errorf("codec %q is not module %q's: a factory's own is %s.<name>", n, module, module)
		}
	}
	return nil
}

// ValidateAgentlessCodecs checks that no target whose codec an agentless
// channel cannot speak (Codec.Agentless) connects through an agentless
// kind: agentless kinds take core's codec. agentless says whether a
// channel acts as the minion on a kind (ConnectionSchema.IsAgentless).
func ValidateAgentlessCodecs(s BuildSchema, agentless func(module, kind string) bool) error {
	for _, t := range s.Targets {
		c := s.TargetCodec(t)
		if c.Agentless() {
			continue
		}
		for _, ch := range s.Channels {
			for _, k := range s.TargetKinds(t, ch.ModuleName) {
				if agentless(ch.ModuleName, k) {
					return fmt.Errorf("target %q: channel %q kind %s is agentless and takes core's codec, not envelope %q with suite %q",
						t.ID, ch.ModuleName, k, c.Envelope, c.Suite)
				}
			}
		}
	}
	return nil
}
