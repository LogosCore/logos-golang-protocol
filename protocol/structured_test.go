package protocol

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func structuredParam(mod func(*FieldSpec)) FieldSpec {
	p := FieldSpec{Key: "targets", Type: FieldStructured, Label: "Targets"}
	if mod != nil {
		mod(&p)
	}
	return p
}

// jsonValue decodes s as core takes a value: numbers as json.Number.
func jsonValue(t *testing.T, s string) any {
	t.Helper()
	d := json.NewDecoder(strings.NewReader(s))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// nested is a value depth levels deep: arrays in arrays, a string inside.
func nested(depth int) any {
	var v any = "x"
	for range depth {
		v = []any{v}
	}
	return v
}

func TestStructuredParamChecks(t *testing.T) {
	ok := []FieldSpec{
		structuredParam(nil),
		structuredParam(func(p *FieldSpec) { p.Required = true; p.MaxSize = 1024; p.Advanced = true }),
		structuredParam(func(p *FieldSpec) { p.Default = map[string]any{"hosts": []any{"a", "b"}, "port": 22.0} }),
	}
	for i, p := range ok {
		if err := checkCommandParam(p); err != nil {
			t.Errorf("ok %d: %v", i, err)
		}
	}
	bad := map[string]FieldSpec{
		"not one core knows": structuredParam(func(p *FieldSpec) { p.Format = "hosts" }),
		"max_size must be":   structuredParam(func(p *FieldSpec) { p.MaxSize = MaxStructuredSize + 1 }),
		"no other rules":     structuredParam(func(p *FieldSpec) { p.Pattern = "^a$" }),
		"default: at .a":     structuredParam(func(p *FieldSpec) { p.Default = map[string]any{"a": nil} }),
		"key must match":     structuredParam(func(p *FieldSpec) { p.Key = "Targets" }),
	}
	for want, p := range bad {
		if err := checkCommandParam(p); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v", want, err)
		}
	}
	// A command's params alone: a build's field, a connection's and a
	// module's own refuse it.
	for name, check := range map[string]func(FieldSpec) error{
		"build": validateBuildFieldSpec, "connection": validateConnectionFieldSpec, "module": validateFieldSpec,
	} {
		if err := check(structuredParam(nil)); err == nil || !strings.Contains(err.Error(), "only for a command's params") {
			t.Errorf("%s field: got %v", name, err)
		}
	}
}

func TestStructuredTaskArg(t *testing.T) {
	params := []FieldSpec{structuredParam(func(p *FieldSpec) { p.Num = 1 })}
	value := jsonValue(t, `{"hosts": [{"name": "a", "port": 22}, {"name": "b", "port": 2222, "weight": 0.5}],
		"big": 18446744073709551615, "exp": 1e3, "on": true}`)
	args, problems := TaskArgs(params, map[string]any{"targets": value})
	if problems != nil {
		t.Fatal(problems)
	}
	m := args["targets"].(map[string]any)
	hosts := m["hosts"].([]any)
	if p := hosts[0].(map[string]any)["port"]; p != int64(22) {
		t.Errorf("an integer: %T %v", p, p)
	}
	if w := hosts[1].(map[string]any)["weight"]; w != 0.5 {
		t.Errorf("a float: %T %v", w, w)
	}
	if m["big"] != uint64(18446744073709551615) || m["exp"] != 1000.0 || m["on"] != true {
		t.Errorf("as written: %#v %#v %#v", m["big"], m["exp"], m["on"])
	}
	// Decoded as float64 (how it was written lost): whole numbers within 2^53
	// are integers.
	if v, _ := structuredForm(map[string]any{"n": 3.0, "f": 3.25}, "", 1); v.(map[string]any)["n"] != int64(3) ||
		v.(map[string]any)["f"] != 3.25 {
		t.Errorf("from float64: %#v", v)
	}

	// The minion reads it back from the task, as it reads every message.
	var got struct {
		Hosts []struct {
			Name   string  `cbor:"name"`
			Port   int     `cbor:"port"`
			Weight float64 `cbor:"weight"`
		} `cbor:"hosts"`
	}
	raw, err := cborEnc.Marshal(TaskItem{T: ItemTask, Task: bytes.Repeat([]byte{1}, 16), Cmd: 7, Args: WireArgs(params, args)})
	if err != nil {
		t.Fatal(err)
	}
	var item TaskItem
	if err := cborDec.Unmarshal(raw, &item); err != nil {
		t.Fatal(err)
	}
	if ok, err := ArgStructured(item.Args, uint64(1), &got); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if len(got.Hosts) != 2 || got.Hosts[1].Name != "b" || got.Hosts[1].Port != 2222 || got.Hosts[1].Weight != 0.5 {
		t.Errorf("read back: %+v", got)
	}
	if ok, _ := ArgStructured(item.Args, uint64(2), &got); ok {
		t.Error("a task without the arg")
	}
}

func TestStructuredValueRefusals(t *testing.T) {
	p := structuredParam(func(p *FieldSpec) { p.MaxSize = 64 })
	cases := map[string]any{
		"at .a[1]: null is not taken": jsonValue(t, `{"a": [1, null]}`),
		"larger than 64 bytes":        strings.Repeat("x", 70),
		"nested deeper than":          nested(MaxStructuredDepth + 1),
		"no JSON value":               struct{}{},
	}
	for want, v := range cases {
		if err := ValidateValue(p, v); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v", want, err)
		}
	}
	if err := ValidateValue(structuredParam(func(p *FieldSpec) { p.Required = true }), nil); err == nil {
		t.Error("a required value left out")
	}
	if err := ValidateValue(p, nested(MaxStructuredDepth)); err != nil {
		t.Errorf("the deepest value: %v", err)
	}
}

// The deepest value core takes is one a minion decodes, inside a message:
// MaxStructuredDepth leaves the task's own levels to the decoder's limit.
func TestStructuredDepthFitsAMessage(t *testing.T) {
	encode := func(v any) []byte {
		item, err := cborEnc.Marshal(TaskItem{T: ItemTask, Task: bytes.Repeat([]byte{1}, 16), Cmd: 7, Args: Args{1: v}})
		if err != nil {
			t.Fatal(err)
		}
		msg, err := cborEnc.Marshal(CoreMessage{V: 3, ID: bytes.Repeat([]byte{2}, 16), Items: []cbor.RawMessage{item}})
		if err != nil {
			t.Fatal(err)
		}
		return msg
	}
	var m CoreMessage
	if err := cborDec.Unmarshal(encode(nested(MaxStructuredDepth)), &m); err != nil {
		t.Fatalf("the deepest value core takes: %v", err)
	}
	if err := cborDec.Unmarshal(encode(nested(MaxStructuredDepth+1)), &m); err == nil {
		t.Fatal("one level deeper decodes too: MaxStructuredDepth is below what a minion takes")
	}
}
