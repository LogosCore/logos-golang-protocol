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
	raw, err := MarshalCBOR(TaskItem{T: ItemTask, Task: make([]byte, 16), Cmd: "shell", Args: args})
	if err != nil {
		t.Fatal(err)
	}
	var task TaskItem
	if err := UnmarshalCBOR(raw, &task); err != nil {
		t.Fatal(err)
	}
	if d, ok := ArgDuration(task.Args, "timeout"); !ok || d != 30*time.Second {
		t.Fatalf("timeout %v %v", d, ok)
	}
	if s, ok := ArgString(task.Args, "command"); !ok || s != "whoami" {
		t.Fatalf("command %q", s)
	}
	if n, ok := ArgInt(task.Args, "jitter"); !ok || n != 10 {
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
