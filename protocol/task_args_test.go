package protocol

import (
	"testing"
	"time"
)

func TestTaskArgs(t *testing.T) {
	params := []FieldSpec{
		{Key: "command", Type: FieldString, Required: true},
		{Key: "timeout", Type: FieldDuration, Default: "30s"},
		{Key: "jitter", Type: FieldInt, Min: 0, Max: 100, Default: 10},
		{Key: "at", Type: FieldDatetime},
		{Key: "tags", Type: FieldStringList},
	}
	args, problems := TaskArgs(params, map[string]any{"command": "whoami", "at": "2026-10-31T10:00:00Z", "tags": []any{"a"}})
	if problems != nil {
		t.Fatalf("problems %v", problems)
	}
	if args["command"] != "whoami" || args["timeout"] != uint64(30000) || args["jitter"] != int64(10) ||
		args["at"] != int64(1793440800) || len(args["tags"].([]string)) != 1 {
		t.Fatalf("args %#v", args)
	}
	// Through CBOR and back, as the minion reads them.
	for i := range params {
		params[i].Num = i + 1
	}
	raw, err := MarshalCBOR(TaskItem{T: ItemTask, Task: make([]byte, 16), Cmd: 11, Args: WireArgs(params, args)})
	if err != nil {
		t.Fatal(err)
	}
	var task TaskItem
	if err := UnmarshalCBOR(raw, &task); err != nil {
		t.Fatal(err)
	}
	if d, ok := ArgDuration(task.Args, 2); !ok || d != 30*time.Second {
		t.Fatalf("timeout %v %v", d, ok)
	}
	if s, ok := ArgString(task.Args, 1); !ok || s != "whoami" {
		t.Fatalf("command %q", s)
	}
	if n, ok := ArgInt(task.Args, 3); !ok || n != 10 {
		t.Fatalf("jitter %d", n)
	}

	// A whole float reads as an integer; a fraction does not.
	if d, ok := ArgDuration(map[string]any{"t": float64(2000)}, "t"); !ok || d != 2*time.Second {
		t.Fatalf("a float duration: %v %v", d, ok)
	}
	if _, ok := ArgInt(map[string]any{"n": 2.5}, "n"); ok {
		t.Fatal("2.5 read as an integer")
	}

	for name, values := range map[string]map[string]any{
		"missing required": {},
		"undeclared":       {"command": "x", "nope": 1},
		"bad duration":     {"command": "x", "timeout": "soon"},
		"over max":         {"command": "x", "jitter": 101},
	} {
		if _, problems := TaskArgs(params, values); problems == nil {
			t.Errorf("%s: no problems", name)
		}
	}
}

// FieldJSONValue undoes TaskArgs's conversion: what TaskArgs makes of a
// value reads back as a value TaskArgs takes, the same.
func TestFieldJSONValue(t *testing.T) {
	params := []FieldSpec{
		{Key: "every", Type: FieldDuration}, {Key: "long", Type: FieldDuration}, {Key: "at", Type: FieldDatetime},
		{Key: "n", Type: FieldInt}, {Key: "s", Type: FieldString},
	}
	in := map[string]any{"every": "1s", "long": "1m30s", "at": "2026-11-21T15:00:00Z", "n": int64(7), "s": "/new/2"}
	args, p := TaskArgs(params, in)
	if p != nil {
		t.Fatal(p)
	}
	back := map[string]any{}
	for _, f := range params {
		back[f.Key] = FieldJSONValue(f, args[f.Key])
	}
	if back["every"] != "1s" || back["long"] != "1m30s" || back["at"] != "2026-11-21T15:00:00Z" || back["n"] != int64(7) || back["s"] != "/new/2" {
		t.Fatalf("read back %v", back)
	}
	if again, p := TaskArgs(params, back); p != nil || again["every"] != args["every"] || again["at"] != args["at"] {
		t.Fatalf("taken again: %v %v", again, p)
	}
	// As a minion says them: CBOR's unsigned integers; and a value already
	// JSON's stays.
	if got := FieldJSONValue(params[0], uint64(40000)); got != "40s" {
		t.Fatalf("40000 ms: %v", got)
	}
	if got := FieldJSONValue(params[0], "30s"); got != "30s" {
		t.Fatalf("a duration's text: %v", got)
	}
}
