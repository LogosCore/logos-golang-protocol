package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

// Structured values (docs: contracts/minion-build.md, Structured values): a
// command's param that takes any JSON value, and carries it in its CBOR form
// inside the task. Its format names what the value is, and core checks the
// value against it.

// FieldStructured is a structured value: command params only.
const FieldStructured FieldType = "structured"

const (
	// MaxStructuredSize is the largest structured value, in bytes of its
	// CBOR form, and the limit of a param without max_size.
	MaxStructuredSize = 64 << 10
	// MaxStructuredDepth is how deep a structured value nests, its top
	// level counted: what a minion's decoder takes (maxMinionNesting) under
	// the task's own levels (the message, its items, the task, its args).
	MaxStructuredDepth = maxMinionNesting - 4
)

// structuredFormats are the formats core checks a structured value
// against: "" (none) any JSON value, checked for size and depth alone. A
// format adds its check here, and its row on the docs page.
var structuredFormats = map[string]func(any) error{
	"":               nil,
	FormatConnection: checkConnectionValue,
}

// StructuredFormats are the formats a structured param may name, sorted,
// besides no format.
func StructuredFormats() []string {
	var out []string
	for f := range structuredFormats {
		if f != "" {
			out = append(out, f)
		}
	}
	slices.Sort(out)
	return out
}

// checkStructuredParam checks a command's structured param: a format core
// knows, a max_size within MaxStructuredSize, no rules of other types, a
// default that passes its own rules.
func checkStructuredParam(p FieldSpec) error {
	if !keyPattern.MatchString(p.Key) {
		return fmt.Errorf("key must match %s", keyPattern)
	}
	if err := validateText(p.Label, p.Description); err != nil {
		return err
	}
	if _, ok := structuredFormats[p.Format]; !ok {
		known := "none"
		if fs := StructuredFormats(); len(fs) > 0 {
			known = strings.Join(fs, ", ")
		}
		return fmt.Errorf("format %q is not one core knows (%s)", p.Format, known)
	}
	switch {
	case len(p.Platforms) > 0:
		return fmt.Errorf("platforms are only for a build's fields")
	case len(p.Options) > 0 || p.Pattern != "" || p.KeyPattern != "" || p.MaxLength != 0 || p.MaxItems != 0 ||
		p.Min != nil || p.Max != nil || len(p.Accept) > 0:
		return fmt.Errorf("a structured value takes format and max_size, no other rules")
	case p.MaxSize < 0 || p.MaxSize > MaxStructuredSize:
		return fmt.Errorf("max_size must be 1 to %d bytes", MaxStructuredSize)
	}
	if p.Default != nil {
		if err := ValidateValue(p, p.Default); err != nil {
			return fmt.Errorf("default: %w", err)
		}
	}
	return nil
}

// structuredArg is a structured value in its CBOR form, checked: JSON's
// values but null, nested at most MaxStructuredDepth, its CBOR form within
// the param's max_size, and what its format says.
func structuredArg(f FieldSpec, v any) (any, error) {
	out, err := structuredForm(v, "", 1)
	if err != nil {
		return nil, err
	}
	b, err := cborEnc.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("does not encode: %w", err)
	}
	limit := int64(MaxStructuredSize)
	if f.MaxSize > 0 {
		limit = f.MaxSize
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("larger than %d bytes as CBOR (%d)", limit, len(b))
	}
	if check := structuredFormats[f.Format]; check != nil {
		if err := check(out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// structuredForm converts a decoded JSON value (numbers float64,
// json.Number or Go integers) into the values its CBOR form is encoded
// from; at says where a problem is ("" the top, ".a[2]" inside).
func structuredForm(v any, at string, depth int) (any, error) {
	where := func(err string) error {
		if at == "" {
			return fmt.Errorf("%s", err)
		}
		return fmt.Errorf("at %s: %s", at, err)
	}
	switch x := v.(type) {
	case nil:
		return nil, where("null is not taken: leave the value out")
	case string, bool:
		return x, nil
	case map[string]any:
		if depth > MaxStructuredDepth {
			return nil, where(fmt.Sprintf("nested deeper than %d", MaxStructuredDepth))
		}
		out := make(map[string]any, len(x))
		for _, k := range sortedKeys(x) {
			c, err := structuredForm(x[k], at+"."+k, depth+1)
			if err != nil {
				return nil, err
			}
			out[k] = c
		}
		return out, nil
	case []any:
		if depth > MaxStructuredDepth {
			return nil, where(fmt.Sprintf("nested deeper than %d", MaxStructuredDepth))
		}
		out := make([]any, len(x))
		for i, it := range x {
			c, err := structuredForm(it, at+"["+strconv.Itoa(i)+"]", depth+1)
			if err != nil {
				return nil, err
			}
			out[i] = c
		}
		return out, nil
	case map[string]string:
		m := make(map[string]any, len(x))
		for k, s := range x {
			m[k] = s
		}
		return structuredForm(m, at, depth)
	case []string:
		a := make([]any, len(x))
		for i, s := range x {
			a[i] = s
		}
		return structuredForm(a, at, depth)
	case json.Number:
		return jsonNumber(x, where)
	case float64:
		return floatForm(x, where)
	case float32:
		return floatForm(float64(x), where)
	case int:
		return int64(x), nil
	case int32:
		return int64(x), nil
	case int64:
		return x, nil
	case uint64:
		return x, nil
	}
	return nil, where(fmt.Sprintf("a %T is no JSON value", v))
}

// jsonNumber is a number as written: an integer when written without a
// fraction or an exponent and it fits in 64 bits, a float otherwise.
func jsonNumber(n json.Number, where func(string) error) (any, error) {
	s := n.String()
	if !strings.ContainsAny(s, ".eE") {
		if i, err := strconv.ParseInt(s, 10, 64); err == nil {
			return i, nil
		}
		if u, err := strconv.ParseUint(s, 10, 64); err == nil {
			return u, nil
		}
	}
	f, err := n.Float64()
	if err != nil || math.IsInf(f, 0) {
		return nil, where("a number out of range")
	}
	// Written as a float, it stays one (1e3, 2.0).
	return f, nil
}

// floatForm is a number decoded as a float (how it was written is lost): an
// integer when whole and exact in a float (within 2^53), a float otherwise.
func floatForm(f float64, where func(string) error) (any, error) {
	switch {
	case math.IsNaN(f) || math.IsInf(f, 0):
		return nil, where("not a number")
	case f == math.Trunc(f) && math.Abs(f) <= 1<<53:
		return int64(f), nil
	}
	return f, nil
}

// ArgStructured decodes a task's structured arg into out, a pointer (a
// struct with cbor tags, a map, a slice, any): by number in a task's Args,
// or by key in TaskArgs. ok is false when the task has none.
func ArgStructured[K comparable](args map[K]any, key K, out any) (ok bool, err error) {
	v, ok := args[key]
	if !ok {
		return false, nil
	}
	b, err := cborEnc.Marshal(v)
	if err != nil {
		return true, err
	}
	return true, cborDec.Unmarshal(b, out)
}

// A structured value of FormatConnection is one connection, as a build's,
// by names: {"channel", "kind", "version"?, "params"?, "values"?,
// "failover"?, "max_message"?}. Its shape is checked here (TaskArgs); core
// checks it against the channel's fields and the factory's connection
// parameters and puts the minion's numbered form in the arg's place
// (ConnectionArg), as it puts a credential in place of its id.

// checkConnectionValue checks a connection value's shape, in its CBOR form
// (structuredForm): an object of the keys FormatConnection names, a channel,
// one of the connection kinds, params and values objects, a
// failover's auto and fail_after, a max_message within the protocol's.
func checkConnectionValue(v any) error {
	m, ok := v.(map[string]any)
	if !ok {
		return fmt.Errorf("a connection is an object")
	}
	for k := range m {
		switch k {
		case "channel", "kind", "version", "params", "values", "failover", "max_message":
		default:
			return fmt.Errorf("a connection has no %q", k)
		}
	}
	if c, _ := m["channel"].(string); c == "" {
		return fmt.Errorf("a connection's channel is required")
	}
	switch m["kind"] {
	case KindReverseCall, KindReversePersistent, KindBindCall, KindBindPersistent:
	default:
		return fmt.Errorf("a connection's kind is one of %s, %s, %s, %s", KindReverseCall, KindReversePersistent, KindBindCall,
			KindBindPersistent)
	}
	if n, ok := m["version"]; ok {
		if i, ok := AsInt64(n); !ok || i < 0 {
			return fmt.Errorf("a connection's version is a whole number")
		}
	}
	for _, k := range []string{"params", "values"} {
		if x, ok := m[k]; ok {
			if _, ok := x.(map[string]any); !ok {
				return fmt.Errorf("a connection's %s are an object, by key", k)
			}
		}
	}
	if x, ok := m["failover"]; ok {
		f, ok := x.(map[string]any)
		if !ok {
			return fmt.Errorf("a connection's failover is an object")
		}
		for k, fv := range f {
			switch k {
			case "auto":
				if _, ok := fv.(bool); !ok {
					return fmt.Errorf("failover's auto is true or false")
				}
			case "fail_after":
				if i, ok := AsInt64(fv); !ok || i < 1 {
					return fmt.Errorf("failover's fail_after is 1 at least")
				}
			default:
				return fmt.Errorf("a connection's failover has no %q", k)
			}
		}
	}
	if x, ok := m["max_message"]; ok {
		if i, ok := AsInt64(x); !ok || i < 0 || i > MaxMinionMessageSize {
			return fmt.Errorf("a connection's max_message is 0 to %d", MaxMinionMessageSize)
		}
	}
	return nil
}

// ConnectionArg is a connection value (a FormatConnection param's arg, as
// TaskArgs leaves it) as the minion gets it: its params checked against
// channel's fields for its kind and its values against factory's
// connection parameters for its channel and kind, defaults filled in, each
// by its field's number in its type's CBOR form. Problems come by key
// ("params.url"). A credential field takes no value here: a connection
// handed to a minion carries none.
func ConnectionArg(v any, channel, factory []FieldSpec) (HelloConnection, map[string]string) {
	var c HelloConnection
	if err := checkConnectionValue(v); err != nil {
		return c, map[string]string{"": err.Error()}
	}
	m := v.(map[string]any)
	c.Channel, _ = m["channel"].(string)
	c.Kind, _ = m["kind"].(string)
	if n, ok := AsInt64(m["version"]); ok {
		c.Version = uint64(n) //nolint:gosec // checked: not negative
	}
	if n, ok := AsInt64(m["max_message"]); ok {
		c.MaxMessage = uint64(n) //nolint:gosec // checked: within the protocol's
	}
	if f, ok := m["failover"].(map[string]any); ok {
		c.Failover = &HelloConnectionFailover{}
		if a, ok := f["auto"].(bool); ok {
			c.Failover.Auto = &a
		}
		if n, ok := AsInt64(f["fail_after"]); ok {
			c.Failover.FailAfter = uint64(n) //nolint:gosec // checked: 1 at least
		}
	}
	var problems map[string]string
	numbered := func(what string, fields []FieldSpec) map[uint64]any {
		values, _ := m[what].(map[string]any)
		out, p := connectionValues(fields, values)
		for k, r := range p {
			problems = addProblem(problems, what+"."+k, r)
		}
		return out
	}
	c.Params, c.Values = numbered("params", channel), numbered("values", factory)
	if problems != nil {
		return HelloConnection{}, problems
	}
	return c, nil
}

// connectionValues are values checked against fields, over their defaults,
// each in its type's CBOR form by its field's number; nil for none.
func connectionValues(fields []FieldSpec, values map[string]any) (map[uint64]any, map[string]string) {
	for _, f := range fields {
		if isCredentialField(f.Type) && values[f.Key] != nil {
			return nil, map[string]string{f.Key: "a connection handed to a minion carries no credentials"}
		}
	}
	args, problems := TaskArgs(fields, values)
	if problems != nil {
		return nil, problems
	}
	var out map[uint64]any
	for _, f := range fields {
		if a, ok := args[f.Key]; ok && f.Num > 0 && !isCredentialField(f.Type) {
			if out == nil {
				out = map[uint64]any{}
			}
			out[uint64(f.Num)] = a //nolint:gosec // a field's num is 1 to MaxFieldNumber
		}
	}
	return out, nil
}

// ConnectionPatch is what an edit_connection task carries for its
// connection (docs: contracts/task-results-and-actions.md, The patch): what
// changed of the connection at its place. With Channel and Kind (Whole),
// the connection whole, in place of the old one: its params follow another
// schema. Else only what differs: the Params and Values that changed, a nil
// value for one gone, and Version, Failover and MaxMessage when they
// change. DiffConnection makes one; Apply takes it.
type ConnectionPatch struct {
	Channel string `cbor:"1,keyasint,omitempty"`
	Kind    string `cbor:"2,keyasint,omitempty"`
	// 3 was the name: a session's connections have none.
	Version    *uint64                  `cbor:"4,keyasint,omitempty"`
	Params     map[uint64]any           `cbor:"5,keyasint,omitempty"`
	Values     map[uint64]any           `cbor:"6,keyasint,omitempty"`
	Failover   *HelloConnectionFailover `cbor:"7,keyasint,omitempty"`
	MaxMessage *uint64                  `cbor:"8,keyasint,omitempty"`
}

// Whole reports whether p is a connection whole (it names a channel and a
// kind) rather than a difference.
func (p ConnectionPatch) Whole() bool { return p.Channel != "" || p.Kind != "" }

// Empty reports whether p changes nothing.
func (p ConnectionPatch) Empty() bool {
	return !p.Whole() && p.Version == nil && len(p.Params) == 0 && len(p.Values) == 0 && p.Failover == nil &&
		p.MaxMessage == nil
}

// Validate checks p's shape: a channel and a kind together, a whole one as
// a hello's connection; a max_message within the protocol's.
func (p ConnectionPatch) Validate() error {
	if p.Whole() {
		if p.Channel == "" || p.Kind == "" {
			return fmt.Errorf("a connection patch names a channel and a kind together, or neither")
		}
		return p.Apply(HelloConnection{}).Validate()
	}
	if p.MaxMessage != nil && *p.MaxMessage > MaxMinionMessageSize {
		return fmt.Errorf("max_message is %d at most", MaxMinionMessageSize)
	}
	return nil
}

// DiffConnection is what changes old into new, both in their numbered
// forms with defaults filled in (ConnectionArg): new whole when its channel
// or kind differs, else what differs of it.
func DiffConnection(old, new HelloConnection) ConnectionPatch {
	if old.Channel != new.Channel || old.Kind != new.Kind {
		p := ConnectionPatch{Channel: new.Channel, Kind: new.Kind, Params: new.Params, Values: new.Values, Failover: new.Failover}
		if new.Version != 0 {
			p.Version = &new.Version
		}
		if new.MaxMessage != 0 {
			p.MaxMessage = &new.MaxMessage
		}
		return p
	}
	var p ConnectionPatch
	if new.Version != old.Version {
		p.Version = &new.Version
	}
	p.Params, p.Values = diffArgs(old.Params, new.Params), diffArgs(old.Values, new.Values)
	if !equalCBOR(old.Failover, new.Failover) {
		p.Failover = new.Failover
		if p.Failover == nil {
			// None now: the defaults, said.
			p.Failover = &HelloConnectionFailover{}
		}
	}
	if new.MaxMessage != old.MaxMessage {
		p.MaxMessage = &new.MaxMessage
	}
	return p
}

// Apply is old with p made: p whole in its place, or old with what p
// changes.
func (p ConnectionPatch) Apply(old HelloConnection) HelloConnection {
	if p.Whole() {
		c := HelloConnection{Channel: p.Channel, Kind: p.Kind, Params: p.Params, Values: p.Values, Failover: p.Failover}
		if p.Version != nil {
			c.Version = *p.Version
		}
		if p.MaxMessage != nil {
			c.MaxMessage = *p.MaxMessage
		}
		return c
	}
	c := old
	if p.Version != nil {
		c.Version = *p.Version
	}
	c.Params, c.Values = applyArgs(old.Params, p.Params), applyArgs(old.Values, p.Values)
	if p.Failover != nil {
		c.Failover = p.Failover
	}
	if p.MaxMessage != nil {
		c.MaxMessage = *p.MaxMessage
	}
	return c
}

// diffArgs are the numbers whose values differ from old to new, with their
// new values, nil for one new does not have; nil when none differs.
func diffArgs(old, new map[uint64]any) map[uint64]any {
	var out map[uint64]any
	set := func(n uint64, v any) {
		if out == nil {
			out = map[uint64]any{}
		}
		out[n] = v
	}
	for n, v := range new {
		if was, ok := old[n]; !ok || !equalCBOR(was, v) {
			set(n, v)
		}
	}
	for n := range old {
		if _, ok := new[n]; !ok {
			set(n, nil)
		}
	}
	return out
}

// applyArgs is old with changes made: a nil value removes its number.
func applyArgs(old, changes map[uint64]any) map[uint64]any {
	if len(changes) == 0 {
		return old
	}
	out := make(map[uint64]any, len(old)+len(changes))
	for n, v := range old {
		out[n] = v
	}
	for n, v := range changes {
		if v == nil {
			delete(out, n)
		} else {
			out[n] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// canonicalCBOR encodes for comparing: map keys sorted, so equal values
// encode alike (an int and a uint64 of one value too).
var canonicalCBOR, _ = cbor.EncOptions{Sort: cbor.SortCanonical, ShortestFloat: cbor.ShortestFloat16}.EncMode()

// equalCBOR reports whether a and b are the same in CBOR.
func equalCBOR(a, b any) bool {
	ba, ea := canonicalCBOR.Marshal(a)
	bb, eb := canonicalCBOR.Marshal(b)
	return ea == nil && eb == nil && bytes.Equal(ba, bb)
}
