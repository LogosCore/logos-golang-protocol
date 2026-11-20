package protocol

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
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
	"": nil,
}

// StructuredFormats are the formats a structured param may name, sorted:
// none yet, besides no format.
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
