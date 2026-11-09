package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
)

// MessageEnvelope writes a message as plaintext and reads it back: one of core's
// envelopes (codecs.go). The protocol's form of a message, and of an item,
// is CBOR, as MarshalCBOR writes the protocol's types: an envelope maps it
// to its own form and back, so core reads and writes every message as the
// protocol's types, whatever the envelope.
type MessageEnvelope interface {
	// Name is the envelope's name in a build schema (EnvelopeCBOR, ...).
	Name() string
	// WriteMessage is msg, a message in CBOR, in the envelope's form.
	WriteMessage(msg []byte) ([]byte, error)
	// ReadMessage is a message in the envelope's form as CBOR, held to the
	// protocol's limits counted in the envelope's bytes.
	ReadMessage(b []byte) ([]byte, error)
	// WriteItem and ReadItem do the same for one item: what a packed item
	// holds (PackIn, UnpackIn).
	WriteItem(item cbor.RawMessage) ([]byte, error)
	ReadItem(b []byte) (cbor.RawMessage, error)
}

// CoreEnvelope is core's envelope called name (EnvelopeCBOR for ""); false
// for a name core does not have (a factory's).
func CoreEnvelope(name string) (MessageEnvelope, bool) {
	switch name {
	case "", EnvelopeCBOR:
		return CBOREnvelope, true
	case EnvelopeJSON:
		return JSONEnvelope, true
	}
	return nil, false
}

// CBOREnvelope is the message in CBOR: the protocol's form as it is.
var CBOREnvelope MessageEnvelope = cborEnvelope{}

// JSONEnvelope is the message as JSON text (RFC 8259), mapped from the
// CBOR subset one to one (docs: codecs/, The JSON envelope):
//
//   - A map with numbered keys is an object whose names are the keys'
//     numbers in decimal; a map with text keys an object with the same
//     names.
//   - A byte string where the protocol's types say bytes (ids, output, a
//     chunk's data, a frame) is a string, its base64 (RFC 4648 §4,
//     padded). Where they leave the value open (an x, a result's data, a
//     task's args) it is {"$b": "<base64>"}, a name "$b" alone being
//     reserved there; and there an object whose names are all decimal
//     numbers is a map with numbered keys. A reader takes {"$b": ...}
//     wherever bytes go.
//   - An integer is a number without fraction or exponent, within
//     ±(2⁵³ − 1); a float a finite number with one.
//
// It is written compact (UTF-8, no whitespace) and read with whitespace,
// each name once, within the CBOR rules' limits: 16 levels, 65 536
// elements, and the message limit counted in the JSON's bytes. Items are
// read by their type's struct; one the protocol does not know is read as
// open.
var JSONEnvelope MessageEnvelope = jsonEnvelope{}

type cborEnvelope struct{}

func (cborEnvelope) Name() string { return EnvelopeCBOR }

func (cborEnvelope) WriteMessage(msg []byte) ([]byte, error) { return msg, nil }

func (cborEnvelope) ReadMessage(b []byte) ([]byte, error) {
	if len(b) > MaxMinionMessageSize {
		return nil, fmt.Errorf("message of %d bytes is over %d", len(b), MaxMinionMessageSize)
	}
	return b, nil
}

func (cborEnvelope) WriteItem(item cbor.RawMessage) ([]byte, error) { return item, nil }

func (cborEnvelope) ReadItem(b []byte) (cbor.RawMessage, error) { return b, nil }

type jsonEnvelope struct{}

func (jsonEnvelope) Name() string { return EnvelopeJSON }

func (jsonEnvelope) WriteMessage(msg []byte) ([]byte, error) { return cborToJSON(msg, messageShape()) }

func (jsonEnvelope) ReadMessage(b []byte) ([]byte, error) {
	if len(b) > MaxMinionMessageSize {
		return nil, fmt.Errorf("message of %d bytes is over %d", len(b), MaxMinionMessageSize)
	}
	return jsonToCBOR(b, messageShape())
}

func (jsonEnvelope) WriteItem(item cbor.RawMessage) ([]byte, error) {
	return cborToJSON(item, &shape{kind: shapeItem})
}

func (jsonEnvelope) ReadItem(b []byte) (cbor.RawMessage, error) {
	return jsonToCBOR(b, &shape{kind: shapeItem})
}

// itemTypes are the protocol's item structs by their type: what the JSON
// envelope reads an item by.
var itemTypes = map[int]reflect.Type{
	ItemStage: reflect.TypeFor[StageItem](), ItemStageResponse: reflect.TypeFor[StageResponseItem](),
	ItemHello: reflect.TypeFor[HelloItem](), ItemHelloResponse: reflect.TypeFor[HelloResponseItem](),
	ItemSleepUpdate: reflect.TypeFor[SleepUpdateItem](), ItemRehello: reflect.TypeFor[RehelloItem](),
	ItemGetTasks: reflect.TypeFor[GetTasksItem](), ItemTask: reflect.TypeFor[TaskItem](),
	ItemCancel: reflect.TypeFor[CancelItem](), ItemResult: reflect.TypeFor[ResultItem](),
	ItemAck: reflect.TypeFor[AckItem](), ItemChunk: reflect.TypeFor[ChunkItem](), ItemErr: reflect.TypeFor[ErrItem](),
	ItemConnUpdate: reflect.TypeFor[ConnUpdateItem](), ItemResume: reflect.TypeFor[ResumeItem](),
	ItemPoll: reflect.TypeFor[PollItem](), ItemMaxTasks: reflect.TypeFor[MaxTasksItem](),
	ItemFeedback: reflect.TypeFor[FeedbackItem](), ItemReack: reflect.TypeFor[ReackItem](),
	ItemIdentity: reflect.TypeFor[IdentityItem](), ItemTunnel: reflect.TypeFor[TunnelItem](),
	ItemTunnelReply: reflect.TypeFor[TunnelReplyItem](), ItemTunnelData: reflect.TypeFor[TunnelDataItem](),
	ItemTunnelAck: reflect.TypeFor[TunnelAckItem](), ItemTunnelClose: reflect.TypeFor[TunnelCloseItem](),
	ItemTunnelDatagram: reflect.TypeFor[TunnelDatagramItem](), ItemTunnelListen: reflect.TypeFor[TunnelListenItem](),
	ItemTunnelCtl: reflect.TypeFor[TunnelCtlItem](), ItemDelegate: reflect.TypeFor[DelegateItem](),
	ItemPacked: reflect.TypeFor[PackedItem](),
}

// A shape is what the protocol's types say of a value: how the JSON
// envelope writes and reads it.
type shapeKind int

const (
	shapeOpen   shapeKind = iota // no type: an any, a cbor.RawMessage
	shapeBytes                   // []byte
	shapeText                    // string
	shapeScalar                  // a bool or an integer
	shapeFloat                   // a float
	shapeStruct                  // a struct, by its cbor tags
	shapeMap                     // a map: Elem by key
	shapeList                    // a slice: Elem each
	shapeItems                   // a message's items
	shapeItem                    // an item, by its type
)

type shape struct {
	kind shapeKind
	// intKeys: a struct's or a map's keys are numbers.
	intKeys bool
	// fields are a struct's, by key: a uint64 or a string.
	fields map[any]*shape
	elem   *shape
}

var (
	openShape  = &shape{kind: shapeOpen}
	shapeMu    sync.Mutex
	shapeCache = map[reflect.Type]*shape{}
	rawType    = reflect.TypeFor[cbor.RawMessage]()
)

func messageShape() *shape { return shapeOf(reflect.TypeFor[CoreMessage]()) }

func itemShape(t int) *shape {
	if rt, ok := itemTypes[t]; ok {
		return shapeOf(rt)
	}
	return openShape
}

// shapeOf is the shape of a Go type, cached (a struct's shape is cached
// before its fields, so a type that holds itself ends).
func shapeOf(t reflect.Type) *shape {
	shapeMu.Lock()
	defer shapeMu.Unlock()
	return shapeOfLocked(t)
}

func shapeOfLocked(t reflect.Type) *shape {
	if s, ok := shapeCache[t]; ok {
		return s
	}
	switch {
	case t == rawType:
		return openShape
	case t.Kind() == reflect.Pointer:
		return shapeOfLocked(t.Elem())
	case t.Kind() == reflect.Slice && t.Elem() == rawType:
		return &shape{kind: shapeItems}
	case (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) && t.Elem().Kind() == reflect.Uint8:
		return &shape{kind: shapeBytes}
	case t.Kind() == reflect.Slice || t.Kind() == reflect.Array:
		return &shape{kind: shapeList, elem: shapeOfLocked(t.Elem())}
	case t.Kind() == reflect.String:
		return &shape{kind: shapeText}
	case t.Kind() == reflect.Float32 || t.Kind() == reflect.Float64:
		return &shape{kind: shapeFloat}
	case t.Kind() == reflect.Bool || t.Kind() >= reflect.Int && t.Kind() <= reflect.Uint64:
		return &shape{kind: shapeScalar}
	case t.Kind() == reflect.Map:
		k := t.Key().Kind()
		return &shape{kind: shapeMap, intKeys: k >= reflect.Int && k <= reflect.Uint64, elem: shapeOfLocked(t.Elem())}
	case t.Kind() == reflect.Struct:
		s := &shape{kind: shapeStruct, fields: map[any]*shape{}, intKeys: true}
		shapeCache[t] = s
		for i := range t.NumField() {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			name, opts, _ := strings.Cut(f.Tag.Get("cbor"), ",")
			if name == "-" {
				continue
			}
			if name == "" {
				name = f.Name
			}
			if slices.Contains(strings.Split(opts, ","), "keyasint") {
				if n, err := strconv.ParseUint(name, 10, 64); err == nil {
					s.fields[n] = shapeOfLocked(f.Type)
					continue
				}
			}
			s.intKeys = false
			s.fields[name] = shapeOfLocked(f.Type)
		}
		return s
	}
	return openShape
}

// field is the shape of a struct's or a map's value under key.
func (s *shape) field(key any) *shape {
	switch s.kind {
	case shapeStruct:
		if f, ok := s.fields[key]; ok {
			return f
		}
	case shapeMap:
		return s.elem
	}
	return openShape
}

// maxJSONInt bounds a JSON integer: ±(2⁵³ − 1), what every reader of JSON
// numbers holds exactly.
const maxJSONInt = 1<<53 - 1

var (
	errJSONInt = fmt.Errorf("an integer is within ±%d", maxJSONInt)
	// decimalName is a name that is a number in decimal, a numbered key.
	decimalName = regexp.MustCompile(`^(0|[1-9][0-9]{0,15})$`)
)

// jsonTreeDec reads CBOR with the formats' rules into a tree the JSON
// writer walks: maps keyed by numbers and text alike.
var jsonTreeDec = func() cbor.DecMode {
	d, err := cbor.DecOptions{
		DupMapKey: cbor.DupMapKeyEnforcedAPF, IndefLength: cbor.IndefLengthForbidden, TagsMd: cbor.TagsForbidden,
		MaxNestedLevels: maxMinionNesting, MaxArrayElements: MaxMinionNestedElements, MaxMapPairs: MaxMinionNestedElements,
		UTF8: cbor.UTF8RejectInvalid, DefaultMapType: reflect.TypeFor[map[any]any](),
	}.DecMode()
	if err != nil {
		panic(err)
	}
	return d
}()

// cborToJSON writes CBOR as the JSON envelope, by s.
func cborToJSON(b []byte, s *shape) ([]byte, error) {
	if len(b) > MaxMinionMessageSize {
		return nil, fmt.Errorf("message of %d bytes is over %d", len(b), MaxMinionMessageSize)
	}
	var v any
	if err := jsonTreeDec.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("json envelope: %w", err)
	}
	out, err := appendJSON(make([]byte, 0, len(b)*3/2), v, s)
	if err != nil {
		return nil, fmt.Errorf("json envelope: %w", err)
	}
	return out, nil
}

func appendJSON(out []byte, v any, s *shape) ([]byte, error) {
	switch v := v.(type) {
	case nil:
		return append(out, "null"...), nil
	case bool:
		return strconv.AppendBool(out, v), nil
	case uint64:
		if v > maxJSONInt {
			return nil, errJSONInt
		}
		return strconv.AppendUint(out, v, 10), nil
	case int64:
		if v < -maxJSONInt || v > maxJSONInt {
			return nil, errJSONInt
		}
		return strconv.AppendInt(out, v, 10), nil
	case float64:
		if math.IsInf(v, 0) || math.IsNaN(v) {
			return nil, errors.New("a float is finite")
		}
		n := len(out)
		out = strconv.AppendFloat(out, v, 'g', -1, 64)
		if !bytes.ContainsAny(out[n:], ".e") {
			// A float keeps a fraction, so it reads back as one.
			out = append(out, ".0"...)
		}
		return out, nil
	case string:
		return appendJSONString(out, v), nil
	case []byte:
		if s.kind == shapeBytes {
			return appendBase64(out, v), nil
		}
		out = append(out, `{"$b":`...)
		return append(appendBase64(out, v), '}'), nil
	case []any:
		elem := openShape
		switch s.kind {
		case shapeList:
			elem = s.elem
		case shapeItems:
			elem = &shape{kind: shapeItem}
		}
		out = append(out, '[')
		for i, e := range v {
			if i > 0 {
				out = append(out, ',')
			}
			var err error
			if out, err = appendJSON(out, e, elem); err != nil {
				return nil, err
			}
		}
		return append(out, ']'), nil
	case map[any]any:
		if s.kind == shapeItem {
			t, _ := v[uint64(0)].(uint64)
			s = itemShape(int(min(t, math.MaxInt32)))
		}
		keys, numbered, err := mapKeys(v)
		if err != nil {
			return nil, err
		}
		if !numbered && len(keys) == 1 && keys[0] == "$b" && s.kind != shapeStruct && s.kind != shapeMap {
			return nil, errors.New(`a map whose one key is "$b" is bytes where the protocol's types leave a value open`)
		}
		out = append(out, '{')
		for i, k := range keys {
			if i > 0 {
				out = append(out, ',')
			}
			if numbered {
				out = append(out, '"')
				out = strconv.AppendUint(out, k.(uint64), 10)
				out = append(out, '"')
			} else {
				out = appendJSONString(out, k.(string))
			}
			out = append(out, ':')
			if out, err = appendJSON(out, v[k], s.field(k)); err != nil {
				return nil, err
			}
		}
		return append(out, '}'), nil
	}
	return nil, fmt.Errorf("a value JSON does not hold: %T", v)
}

// mapKeys are m's keys in order, numbers or text: numbered says which.
// A map with keys of both kinds, or of another, has no JSON form.
func mapKeys(m map[any]any) (keys []any, numbered bool, err error) {
	var nums []uint64
	var texts []string
	for k := range m {
		switch k := k.(type) {
		case uint64:
			if k > maxJSONInt {
				return nil, false, errJSONInt
			}
			nums = append(nums, k)
		case string:
			texts = append(texts, k)
		default:
			return nil, false, fmt.Errorf("a map key is a number or text, not %T", k)
		}
	}
	if len(nums) > 0 && len(texts) > 0 {
		return nil, false, errors.New("a map's keys are numbers or text, not both")
	}
	slices.Sort(nums)
	slices.Sort(texts)
	for _, n := range nums {
		keys = append(keys, n)
	}
	for _, t := range texts {
		keys = append(keys, t)
	}
	return keys, len(nums) > 0, nil
}

func appendBase64(out []byte, b []byte) []byte {
	out = append(out, '"')
	out = base64.StdEncoding.AppendEncode(out, b)
	return append(out, '"')
}

// appendJSONString writes s as a JSON string: quotes, backslashes and
// control characters escaped, the rest as it is.
func appendJSONString(out []byte, s string) []byte {
	const hex = "0123456789abcdef"
	out = append(out, '"')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"' || c == '\\':
			out = append(out, '\\', c)
		case c == '\n':
			out = append(out, '\\', 'n')
		case c == '\r':
			out = append(out, '\\', 'r')
		case c == '\t':
			out = append(out, '\\', 't')
		case c < 0x20:
			out = append(out, '\\', 'u', '0', '0', hex[c>>4], hex[c&0xf])
		default:
			out = append(out, c)
		}
	}
	return append(out, '"')
}

// jsonObject is a JSON object as it was written: its names in order.
type jsonObject struct {
	names []string
	vals  []any
}

func (o *jsonObject) get(name string) (any, bool) {
	if i := slices.Index(o.names, name); i >= 0 {
		return o.vals[i], true
	}
	return nil, false
}

// jsonToCBOR reads the JSON envelope as CBOR, by s.
func jsonToCBOR(b []byte, s *shape) ([]byte, error) {
	if !utf8.Valid(b) {
		return nil, errors.New("json envelope: not UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	v, err := readJSON(d, 0)
	if err != nil {
		return nil, fmt.Errorf("json envelope: %w", err)
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("json envelope: more after the value")
	}
	out, err := appendCBOR(make([]byte, 0, len(b)), v, s)
	if err != nil {
		return nil, fmt.Errorf("json envelope: %w", err)
	}
	return out, nil
}

// readJSON reads one value into a tree: objects as jsonObject, numbers as
// json.Number, with the formats' limits.
func readJSON(d *json.Decoder, depth int) (any, error) {
	tok, err := d.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return tok, nil
	}
	if depth >= maxMinionNesting {
		return nil, fmt.Errorf("more than %d levels", maxMinionNesting)
	}
	switch delim {
	case '[':
		var list []any
		for d.More() {
			if len(list) == MaxMinionNestedElements {
				return nil, fmt.Errorf("an array of more than %d elements", MaxMinionNestedElements)
			}
			v, err := readJSON(d, depth+1)
			if err != nil {
				return nil, err
			}
			list = append(list, v)
		}
		_, err := d.Token()
		return append([]any{}, list...), err
	case '{':
		o := &jsonObject{}
		seen := map[string]bool{}
		for d.More() {
			if len(o.names) == MaxMinionNestedElements {
				return nil, fmt.Errorf("an object of more than %d names", MaxMinionNestedElements)
			}
			tok, err := d.Token()
			if err != nil {
				return nil, err
			}
			name := tok.(string)
			if seen[name] {
				return nil, fmt.Errorf("the name %q twice", name)
			}
			seen[name] = true
			v, err := readJSON(d, depth+1)
			if err != nil {
				return nil, err
			}
			o.names, o.vals = append(o.names, name), append(o.vals, v)
		}
		_, err := d.Token()
		return o, err
	}
	return nil, fmt.Errorf("unexpected %v", delim)
}

func appendCBOR(out []byte, v any, s *shape) ([]byte, error) {
	switch v := v.(type) {
	case nil:
		return append(out, 0xf6), nil
	case bool:
		if v {
			return append(out, 0xf5), nil
		}
		return append(out, 0xf4), nil
	case json.Number:
		return appendCBORNumber(out, string(v), s.kind == shapeFloat)
	case string:
		if s.kind == shapeBytes {
			b, err := base64.StdEncoding.Strict().DecodeString(v)
			if err != nil {
				return nil, errors.New("bytes are base64, padded")
			}
			return append(cborHead(out, 2, uint64(len(b))), b...), nil
		}
		return append(cborHead(out, 3, uint64(len(v))), v...), nil
	case []any:
		elem := openShape
		switch s.kind {
		case shapeList:
			elem = s.elem
		case shapeItems:
			elem = &shape{kind: shapeItem}
		}
		out = cborHead(out, 4, uint64(len(v)))
		for _, e := range v {
			var err error
			if out, err = appendCBOR(out, e, elem); err != nil {
				return nil, err
			}
		}
		return out, nil
	case *jsonObject:
		return appendCBORObject(out, v, s)
	}
	return nil, fmt.Errorf("a value of %T", v)
}

func appendCBORObject(out []byte, o *jsonObject, s *shape) ([]byte, error) {
	if len(o.names) == 1 && o.names[0] == "$b" && s.kind != shapeStruct && s.kind != shapeMap {
		b, ok := o.vals[0].(string)
		if !ok {
			return nil, errors.New(`"$b" holds bytes as base64`)
		}
		return appendCBOR(out, b, &shape{kind: shapeBytes})
	}
	if s.kind == shapeItem {
		s = openShape
		if t, ok := o.get("0"); ok {
			if n, ok := t.(json.Number); ok {
				if i, err := strconv.ParseInt(string(n), 10, 32); err == nil {
					s = itemShape(int(i))
				}
			}
		}
	}
	// An open object whose names all are numbers in decimal is a map with
	// numbered keys.
	allNumbers := len(o.names) > 0
	for _, n := range o.names {
		allNumbers = allNumbers && isDecimalName(n)
	}
	out = cborHead(out, 5, uint64(len(o.names)))
	for i, name := range o.names {
		var key any = name
		switch {
		case s.kind == shapeStruct:
			// A field's own key; past the fields, a number in a struct
			// with numbered keys.
			if _, text := s.fields[name]; !text && s.intKeys && isDecimalName(name) {
				key, _ = strconv.ParseUint(name, 10, 64)
			}
		case s.kind == shapeMap && s.intKeys:
			if !isDecimalName(name) {
				return nil, fmt.Errorf("the name %q is not a number in decimal", name)
			}
			key, _ = strconv.ParseUint(name, 10, 64)
		case s.kind != shapeMap && allNumbers:
			key, _ = strconv.ParseUint(name, 10, 64)
		}
		switch k := key.(type) {
		case uint64:
			out = cborHead(out, 0, k)
		case string:
			out = append(cborHead(out, 3, uint64(len(k))), k...)
		}
		var err error
		if out, err = appendCBOR(out, o.vals[i], s.field(key)); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// appendCBORNumber writes a JSON number: an integer when it has no
// fraction or exponent (and the place is not a float's), else a float.
func appendCBORNumber(out []byte, n string, float bool) ([]byte, error) {
	if !float && !strings.ContainsAny(n, ".eE") {
		i, err := strconv.ParseInt(n, 10, 64)
		if err != nil || i < -maxJSONInt || i > maxJSONInt {
			return nil, errJSONInt
		}
		if i < 0 {
			return cborHead(out, 1, uint64(-1-i)), nil
		}
		return cborHead(out, 0, uint64(i)), nil
	}
	f, err := strconv.ParseFloat(n, 64)
	if err != nil || math.IsInf(f, 0) {
		return nil, errors.New("a float is finite")
	}
	b, err := cborEnc.Marshal(f)
	if err != nil {
		return nil, err
	}
	return append(out, b...), nil
}

// isDecimalName reports whether a name is a number in decimal within a
// JSON integer's bounds: a numbered key.
func isDecimalName(name string) bool {
	if !decimalName.MatchString(name) {
		return false
	}
	n, err := strconv.ParseUint(name, 10, 64)
	return err == nil && n <= maxJSONInt
}

// cborHead writes a CBOR head, its argument in the shortest form.
func cborHead(out []byte, major byte, n uint64) []byte {
	m := major << 5
	switch {
	case n < 24:
		return append(out, m|byte(n))
	case n <= math.MaxUint8:
		return append(out, m|24, byte(n))
	case n <= math.MaxUint16:
		return append(out, m|25, byte(n>>8), byte(n))
	case n <= math.MaxUint32:
		return append(out, m|26, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	return append(out, m|27, byte(n>>56), byte(n>>48), byte(n>>40), byte(n>>32), byte(n>>24), byte(n>>16), byte(n>>8),
		byte(n))
}
