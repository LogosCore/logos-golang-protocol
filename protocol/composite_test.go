package protocol

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The examples of the Task Outsourcing page (docs:
// contracts/task-outsourcing.md), verbatim: a composite command, a call, a
// decision and a download's end with its file.
const (
	docComposite = `{
  "id": "archive",
  "op": 40,
  "label": "Archive a folder",
  "composite": true,
  "uses": ["ls", "download", "rm"],
  "params": [
    { "key": "path", "num": 1, "type": "string", "label": "Folder" }
  ]
}`

	docComposeRequest = `{
  "task_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "session_id": "1b4e28ba-2fa1-41d2-883f-0016d3cca427",
  "build_id": "5b0c4f6e-8a1d-4c2b-9e7f-3d2a1b0c9e8f",
  "seq": 3,
  "event": "ended",
  "deadline": "2026-11-20T14:30:10Z",
  "command": "archive",
  "args": { "path": "C:\\Users\\alice\\Documents" },
  "actor": { "type": "user", "id": "f140266c-…", "name": "admin" },
  "platform": "windows/amd64",
  "os": "windows",
  "commands": ["sleep", "exit", "ls", "download", "rm", "archive"],
  "own_op": "ended",
  "subtasks_under_way": 0,
  "subtasks_ended": 1,
  "upload_url": "/api/factory/tasks/7c9e6679-7425-40de-944b-e07fc1f90ae7/files?expires=1795185070&sig=…",
  "end": {
    "task_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
    "own_op": true,
    "command": "archive",
    "args": { "path": "C:\\Users\\alice\\Documents" },
    "state": "done",
    "ok": true,
    "data": { "archive": "C:\\Users\\alice\\AppData\\Local\\Temp\\docs.zip" },
    "out": "YXJjaGl2ZWQgMTIgZmlsZXM="
  }
}`

	docDecision = `{
  "run": [
    {
      "command": "download",
      "args": { "path": "C:\\Users\\alice\\AppData\\Local\\Temp\\docs.zip" },
      "key": "fetch",
      "as": "fetch the archive"
    }
  ],
  "after": "10m",
  "ctx": "eyJhcmNoaXZlIjoiQzpcXFVzZXJzXFxhbGljZVxcQXBwRGF0YVxcTG9jYWxcXFRlbXBcXGRvY3MuemlwIn0=",
  "status": "downloading the archive"
}`

	docDownloadEnd = `{
  "task_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
  "command": "download",
  "args": { "path": "C:\\Users\\alice\\AppData\\Local\\Temp\\docs.zip" },
  "key": "fetch",
  "as": "fetch the archive",
  "state": "done",
  "ok": true,
  "data": {
    "xfer": { "$bytes": "…" },
    "path": "C:\\Users\\alice\\AppData\\Local\\Temp\\docs.zip",
    "size": 48213,
    "sha256": { "$bytes": "…" }
  },
  "files": [
    {
      "id": "d4f9a1c2-5b3e-4c7d-8e9f-0a1b2c3d4e5f", "name": "docs.zip", "size": 48213,
      "sha256": "63af51616216a711fb32172e019b127a511e67e1603563840de4724e1d60c9ff",
      "url": "/api/factory/tasks/7c9e6679-7425-40de-944b-e07fc1f90ae7/files/d4f9a1c2-5b3e-4c7d-8e9f-0a1b2c3d4e5f?expires=1795185070&sig=…"
    }
  ]
}`
)

func decodeDoc(t *testing.T, raw string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(raw), v); err != nil {
		t.Fatal(err)
	}
}

// compositeSchema is Minion Build's example schema with the commands the
// page's composite uses (ls, rm), and the composite itself.
func compositeSchema(t *testing.T) BuildSchema {
	t.Helper()
	s := exampleBuildSchema(t)
	path := []FieldSpec{{Key: "path", Num: 1, Type: FieldString, Label: "Path", Required: true}}
	s.Commands = append(s.Commands,
		BuildCommand{ID: "ls", Op: 6, Label: "List a directory", Params: path},
		BuildCommand{ID: "rm", Op: 7, Label: "Remove a file", Params: path})
	var archive BuildCommand
	decodeDoc(t, docComposite, &archive)
	return withCommand(s, archive)
}

func withCommand(s BuildSchema, c BuildCommand) BuildSchema {
	s.Commands = append(s.Commands, c)
	return s
}

func command(t *testing.T, s *BuildSchema, id string) *BuildCommand {
	t.Helper()
	for i := range s.Commands {
		if s.Commands[i].ID == id {
			return &s.Commands[i]
		}
	}
	t.Fatalf("no command %q", id)
	return nil
}

// reencodes reports whether v writes JSON that reads back into a fresh
// value writing the same.
func reencodes[T any](t *testing.T, v T) {
	t.Helper()
	first, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var again T
	if err := json.Unmarshal(first, &again); err != nil {
		t.Fatal(err)
	}
	second, err := json.Marshal(again)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("round trip changed it:\n%s\n%s", first, second)
	}
}

func TestComposeDocExamples(t *testing.T) {
	s := compositeSchema(t)
	if err := ValidateBuildSchema(s); err != nil {
		t.Fatal(err)
	}
	archive := command(t, &s, "archive")
	if !archive.Composite || !archive.HasOp() || !reflect.DeepEqual(archive.Uses, []string{"ls", "download", "rm"}) {
		t.Fatalf("composite decoded: %+v", archive)
	}

	var r ComposeRequest
	decodeDoc(t, docComposeRequest, &r)
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	if r.Event != ComposeEnded || r.OwnOp != OwnOpEnded || r.Ctx != nil || r.End == nil || !r.End.OwnOp ||
		string(r.End.Out) != "archived 12 files" || r.Actor == nil || r.Actor.Name != "admin" {
		t.Fatalf("call decoded: %+v", r)
	}
	if want := time.Date(2026, 11, 20, 14, 30, 10, 0, time.UTC); !r.Deadline.Equal(want) {
		t.Fatalf("deadline = %v, want %v", r.Deadline, want)
	}

	var d Decision
	decodeDoc(t, docDecision, &d)
	if err := d.ValidateFor(r); err != nil {
		t.Fatal(err)
	}
	var st struct {
		Archive string `json:"archive"`
	}
	switch after, _ := d.Timer(); {
	case after != 10*time.Minute:
		t.Fatalf("after = %v", after)
	case d.Ctx == nil || json.Unmarshal(*d.Ctx, &st) != nil || st.Archive != `C:\Users\alice\AppData\Local\Temp\docs.zip`:
		t.Fatalf("ctx decoded: %q", st.Archive)
	case len(d.Run) != 1 || d.Run[0].Key != "fetch" || d.Status == nil || *d.Status != "downloading the archive":
		t.Fatalf("decision decoded: %+v", d)
	}

	var e ComposeEnd
	decodeDoc(t, docDownloadEnd, &e)
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(e.Files) != 1 || e.Files[0].Name != "docs.zip" || e.Files[0].Size != 48213 || e.Key != "fetch" {
		t.Fatalf("end decoded: %+v", e)
	}

	reencodes(t, r)
	reencodes(t, d)
	reencodes(t, e)
	reencodes(t, *archive)
}

func TestCompositeSchemaChecks(t *testing.T) {
	noOp := func(s *BuildSchema) {
		c := command(t, s, "archive")
		c.Op, c.Params[0].Num = 0, 0
	}
	cases := []struct {
		name string
		edit func(s *BuildSchema)
		want string // "": valid
	}{
		{"the page's", func(*BuildSchema) {}, ""},
		{"no op of its own", noOp, ""},
		{"two with no op of their own", func(s *BuildSchema) {
			noOp(s)
			*s = withCommand(*s, BuildCommand{ID: "backup", Composite: true, Uses: []string{"ls"}})
		}, ""},
		{"using itself, with an op", func(s *BuildSchema) {
			c := command(t, s, "archive")
			c.Uses = append(c.Uses, "archive")
		}, ""},
		{"using a composite with an op", func(s *BuildSchema) {
			*s = withCommand(*s, BuildCommand{ID: "sweep", Op: 8, Composite: true, Uses: []string{"archive"}})
		}, ""},
		{"on its uses' targets alone", func(s *BuildSchema) {
			c := command(t, s, "archive")
			c.Targets, c.Uses = []string{"windows-exe"}, []string{"screenshot"}
		}, ""},
		{"an action, its params and result", func(s *BuildSchema) {
			c := command(t, s, "archive")
			c.Action, c.Result, c.Params[0].Key = ActionListDir, ResultDirListing, "path"
		}, ""},
		{"uses, not composite", func(s *BuildSchema) { command(t, s, "shell").Uses = []string{"ls"} },
			"only a composite command uses others"},
		{"composite, no uses", func(s *BuildSchema) { command(t, s, "archive").Uses = nil },
			"names the commands its subtasks run"},
		{"a use twice", func(s *BuildSchema) { command(t, s, "archive").Uses = []string{"ls", "ls"} }, `"ls" is named twice`},
		{"a use no command", func(s *BuildSchema) { command(t, s, "archive").Uses = []string{"ls", "cp"} },
			`"cp" is not a command of this factory`},
		{"a use with no op", func(s *BuildSchema) {
			*s = withCommand(*s, BuildCommand{ID: "backup", Composite: true, Uses: []string{"ls"}})
			command(t, s, "archive").Uses = []string{"backup"}
		}, `"backup" has no op of its own`},
		{"using itself, with no op", func(s *BuildSchema) {
			noOp(s)
			command(t, s, "archive").Uses = []string{"ls", "archive"}
		}, `"archive" has no op of its own`},
		{"a use on fewer targets", func(s *BuildSchema) { command(t, s, "archive").Uses = []string{"screenshot"} },
			`"screenshot" is not on target`},
		{"a tunnel", func(s *BuildSchema) {
			c := command(t, s, "archive")
			c.Params, c.Action = nil, ActionTunnel
		}, "a composite is no tunnel and no delegate"},
		{"a delegate", func(s *BuildSchema) {
			c := command(t, s, "archive")
			c.Params, c.Action = nil, ActionDelegate
		}, "a composite is no tunnel and no delegate"},
		{"no op, a numbered param", func(s *BuildSchema) { command(t, s, "archive").Op = 0 }, "numbers no params"},
		{"no op, a stream", func(s *BuildSchema) {
			noOp(s)
			c := command(t, s, "archive")
			c.Params = append(c.Params, FieldSpec{Key: "data", Type: FieldStream, Label: "Data"})
		}, "takes no stream"},
		{"an op past the limit", func(s *BuildSchema) { command(t, s, "archive").Op = MaxCommandNumber + 1 }, "op must be 1 to"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := compositeSchema(t)
			tc.edit(&s)
			err := ValidateBuildSchema(s)
			switch {
			case tc.want == "" && err != nil:
				t.Fatal(err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestPickAndSessionCommands(t *testing.T) {
	s := compositeSchema(t)
	s = withCommand(s, BuildCommand{ID: "backup", Composite: true, Uses: []string{"ls", "download"}})
	s = withCommand(s, BuildCommand{ID: "sweep", Op: 8, Composite: true, Uses: []string{"archive"}})
	if err := ValidateBuildSchema(s); err != nil {
		t.Fatal(err)
	}
	exe := target(t, s, "windows-exe")

	// What a composite uses comes with it, and what that uses: the
	// required ones too, in the schema's order; one with no op builds
	// nothing.
	build := s.PickCommands(exe, "windows/amd64", []string{"sweep", "backup"})
	if want := []string{"sleep", "exit", "download", "ls", "rm", "archive", "sweep"}; !reflect.DeepEqual(build, want) {
		t.Fatalf("picked %v, want %v", build, want)
	}
	if got, want := s.SessionCommands(exe, "windows/amd64", build), []string{"sleep", "exit", "download", "ls", "rm", "archive", "backup", "sweep"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("session has %v, want %v", got, want)
	}
	// A session whose build lacks what it uses has no composite with no op.
	if got, want := s.SessionCommands(exe, "windows/amd64", []string{"sleep", "exit", "download"}), []string{"sleep", "exit", "download"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("session has %v, want %v", got, want)
	}
	// And the builds the picks make are ones a factory takes.
	r := exampleBuildRequest(t)
	r.Commands = build
	if p := ValidateBuildRequest(s, r); p != nil {
		t.Fatalf("problems: %v", p)
	}
}

func TestBuildRequestComposites(t *testing.T) {
	s := withCommand(compositeSchema(t), BuildCommand{ID: "backup", Composite: true, Uses: []string{"ls", "download"}})
	cases := []struct {
		add  []string
		key  string
		want string // "": no problem
	}{
		{[]string{"ls", "rm", "archive"}, "", ""},
		{[]string{"archive"}, "commands[5]", `"archive" uses ls, rm, which the build lacks`},
		{[]string{"ls", "backup"}, "commands[6]", `"backup" builds nothing`},
	}
	for _, tc := range cases {
		r := exampleBuildRequest(t)
		r.Commands = append(r.Commands, tc.add...)
		p := ValidateBuildRequest(s, r)
		switch {
		case tc.want == "" && p != nil:
			t.Errorf("%v: problems %v", tc.add, p)
		case tc.want != "" && (len(p) != 1 || !strings.Contains(p[tc.key], tc.want)):
			t.Errorf("%v: problems %v, want %s: %q", tc.add, p, tc.key, tc.want)
		}
	}
}

func docRequest(t *testing.T) ComposeRequest {
	t.Helper()
	var r ComposeRequest
	decodeDoc(t, docComposeRequest, &r)
	return r
}

func docEnd(t *testing.T) ComposeEnd {
	t.Helper()
	var e ComposeEnd
	decodeDoc(t, docDownloadEnd, &e)
	return e
}

func TestComposeRequestChecks(t *testing.T) {
	subtask := docEnd(t)
	cases := []struct {
		name string
		edit func(r *ComposeRequest)
		want string // "": valid
	}{
		{"the page's", func(*ComposeRequest) {}, ""},
		{"a start", func(r *ComposeRequest) { r.Event, r.End, r.Seq, r.OwnOp = ComposeStart, nil, 1, OwnOpNotRun }, ""},
		{"a subtask's end", func(r *ComposeRequest) { r.End = &subtask }, ""},
		{"a stop, its ends", func(r *ComposeRequest) {
			own := *r.End
			own.State, own.OK, own.Data, own.Out = EndCancelled, false, nil, nil
			refused := ComposeEnd{Command: "rm", Key: "clean", State: EndRefused, Err: "the build lacks rm"}
			r.Event, r.End, r.Ends = ComposeStopped, nil, []ComposeEnd{own, refused}
		}, ""},
		{"no op of its own", func(r *ComposeRequest) { r.OwnOp, r.End = "", &subtask }, ""},
		{"a task id", func(r *ComposeRequest) { r.TaskID = "7C9E6679" }, "task_id must be"},
		{"a session id", func(r *ComposeRequest) { r.SessionID = "" }, "session_id must be"},
		{"a build id", func(r *ComposeRequest) { r.BuildID = "5b0c4f6e" }, "build_id must be"},
		{"seq 0", func(r *ComposeRequest) { r.Seq = 0 }, "seq must be 1 to"},
		{"seq past the calls", func(r *ComposeRequest) { r.Seq = MaxComposeCalls + 1 }, "seq must be 1 to"},
		{"no deadline", func(r *ComposeRequest) { r.Deadline = time.Time{} }, "deadline is required"},
		{"a command", func(r *ComposeRequest) { r.Command = "Archive" }, "command must match"},
		{"a platform", func(r *ComposeRequest) { r.Platform = "windows" }, "platform must be os/arch"},
		{"no os", func(r *ComposeRequest) { r.OS = "" }, "os is required"},
		{"a count", func(r *ComposeRequest) { r.SubtasksEnded = -1 }, "count from 0"},
		{"a ctx", func(r *ComposeRequest) { r.Ctx = make([]byte, MaxComposeCtx+1) }, "ctx longer than"},
		{"an upload url", func(r *ComposeRequest) { r.UploadURL = "files" }, "upload_url must be a link"},
		{"an own op state", func(r *ComposeRequest) { r.OwnOp = "running" }, "own_op must be"},
		{"a command twice", func(r *ComposeRequest) { r.Commands = append(r.Commands, "ls") }, "listed twice"},
		{"an event", func(r *ComposeRequest) { r.Event = "paused" }, "event must be"},
		{"a start with an end", func(r *ComposeRequest) { r.Event = ComposeStart }, "carries no end"},
		{"an end missing", func(r *ComposeRequest) { r.End = nil }, "carries its end"},
		{"ends with an end", func(r *ComposeRequest) { r.Ends = []ComposeEnd{subtask} }, "with a stopped call alone"},
		{"a stop with an end", func(r *ComposeRequest) { r.Event = ComposeStopped }, "carries ends, not an end"},
		{"an own op's end, no op", func(r *ComposeRequest) { r.OwnOp = "" }, "for a command with no op of its own"},
		{"an own op's end, another task", func(r *ComposeRequest) { r.End.TaskID = subtask.TaskID }, "are the task's"},
		{"a bad end", func(r *ComposeRequest) { r.End.State = "lost" }, "end: state must be"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := docRequest(t)
			tc.edit(&r)
			err := r.Validate()
			switch {
			case tc.want == "" && err != nil:
				t.Fatal(err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestComposeEndChecks(t *testing.T) {
	five := int64(5)
	cases := []struct {
		name string
		edit func(e *ComposeEnd)
		want string // "": valid
	}{
		{"the page's", func(*ComposeEnd) {}, ""},
		{"by link", func(e *ComposeEnd) {
			e.Data, e.DataURL, e.OutURL = nil, "/api/factory/tasks/x/data?sig=…", "https://core.example/out"
		}, ""},
		{"refused, no task", func(e *ComposeEnd) { e.TaskID, e.State, e.OK, e.Err, e.Data = "", EndRefused, false, "uses: no", nil }, ""},
		{"cancelled while waiting", func(e *ComposeEnd) { e.TaskID, e.State, e.OK, e.Data = "", EndCancelled, false, nil }, ""},
		{"an exit", func(e *ComposeEnd) { e.Exit = &five }, ""},
		{"a state", func(e *ComposeEnd) { e.State = "lost" }, "state must be"},
		{"done, no task", func(e *ComposeEnd) { e.TaskID = "" }, "task_id is required"},
		{"an own op, no task", func(e *ComposeEnd) {
			e.TaskID, e.Key, e.As, e.OwnOp, e.State, e.OK = "", "", "", true, EndCancelled, false
		},
			"task_id is required"},
		{"a task id", func(e *ComposeEnd) { e.TaskID = "3F2504E0-4F89-41D3-9A0C-0305E82C3301" }, "task_id must be"},
		{"a command", func(e *ComposeEnd) { e.Command = "" }, "command must match"},
		{"an own op's key", func(e *ComposeEnd) { e.OwnOp = true }, "an own op has no key or as"},
		{"ok, cancelled", func(e *ComposeEnd) { e.State = EndCancelled }, "only a done end is ok"},
		{"failed, silent", func(e *ComposeEnd) { e.State, e.OK = EndFailed, false }, "a failed end says why"},
		{"refused, silent", func(e *ComposeEnd) { e.State, e.OK = EndRefused, false }, "a refused end says why"},
		{"an exit, failed", func(e *ComposeEnd) { e.State, e.OK, e.Err, e.Exit = EndFailed, false, "lost", &five },
			"an exit comes with a done end alone"},
		{"data both ways", func(e *ComposeEnd) { e.DataURL = "/api/factory/tasks/x/data" }, "not both"},
		{"out both ways", func(e *ComposeEnd) { e.Out, e.OutURL = []byte("x"), "/api/factory/tasks/x/out" }, "not both"},
		{"data too large", func(e *ComposeEnd) {
			e.Data = json.RawMessage(`{"x":"` + strings.Repeat("a", MaxComposeInline) + `"}`)
		}, "data inline is"},
		{"out too large", func(e *ComposeEnd) { e.Out = make([]byte, MaxComposeInline+1) }, "out inline is"},
		{"a link", func(e *ComposeEnd) { e.Data, e.DataURL = nil, "data" }, "must be links"},
		{"data, no object", func(e *ComposeEnd) { e.Data = json.RawMessage(`[1]`) }, "data must be a JSON object"},
		{"a long key", func(e *ComposeEnd) { e.Key = strings.Repeat("k", MaxSubtaskKey+1) }, "key is 64 bytes at most"},
		{"a key, no text", func(e *ComposeEnd) { e.Key = "a\nb" }, "key must be text"},
		{"a long as", func(e *ComposeEnd) { e.As = strings.Repeat("é", MaxSubtaskLabel+1) }, "as is 120 characters at most"},
		{"as, two lines", func(e *ComposeEnd) { e.As = "fetch\nthe archive" }, "as must be one line"},
		{"a file", func(e *ComposeEnd) { e.Files[0].SHA256 = "63af…" }, "files[0]: sha256"},
		{"a file's link", func(e *ComposeEnd) { e.Files[0].URL = "docs.zip" }, "files[0]: url must be a link"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := docEnd(t)
			tc.edit(&e)
			err := e.Validate()
			switch {
			case tc.want == "" && err != nil:
				t.Fatal(err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestDecisionChecks(t *testing.T) {
	const subtaskID = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
	text := func(s string) *string { return &s }
	notRun := func(r *ComposeRequest) { r.OwnOp = OwnOpNotRun }
	noOp := func(r *ComposeRequest) { r.OwnOp, r.End = "", nil; r.Event = ComposeTimer }
	stopped := func(r *ComposeRequest) { r.Event, r.Ends, r.End = ComposeStopped, []ComposeEnd{*r.End}, nil }
	cases := []struct {
		name string
		call func(r *ComposeRequest) // nil: the page's call
		d    Decision
		want string // "": valid
	}{
		{"nothing: a wait", nil, Decision{}, ""},
		{"a finish and a status", nil, Decision{Finish: &Finish{OK: true, Message: "nothing to archive"}, Status: text("")}, ""},
		{"the own op, not run", notRun, Decision{OwnOp: &OwnOpRun{Args: map[string]any{"path": `C:\`}}}, ""},
		{"a cancel", nil, Decision{Cancel: &ComposeCancel{Keys: []string{"fetch"}, OwnOp: true}}, ""},
		{"a timer of a day", nil, Decision{After: "24h"}, ""},
		{"no op, its own result", noOp, Decision{Finish: &Finish{OK: true, Out: []byte("12 files"), Data: json.RawMessage(`{"n":12}`)}}, ""},
		{"no op, a file's", noOp, Decision{Finish: &Finish{OK: true, OutFile: "d4f9a1c2-5b3e-4c7d-8e9f-0a1b2c3d4e5f"}}, ""},
		{"no op, a subtask's", noOp, Decision{Finish: &Finish{OK: true, ResultOf: subtaskID}}, ""},
		{"a stop takes run alone", stopped, Decision{Run: []Subtask{{Command: "rm"}}, OwnOp: &OwnOpRun{}}, ""},
		{"a finish and a run", nil, Decision{Finish: &Finish{OK: true}, Run: []Subtask{{Command: "rm"}}}, "a finish stands alone"},
		{"a finish and a ctx", nil, Decision{Finish: &Finish{OK: true}, Ctx: &[]byte{}}, "a finish stands alone"},
		{"run past the subtasks", nil, Decision{Run: make([]Subtask, MaxSubtasks+1)}, "run: 1001 subtasks"},
		{"a subtask's command", nil, Decision{Run: []Subtask{{Command: "Rm"}}}, "run[0]: command must match"},
		{"a subtask's as", nil, Decision{Run: []Subtask{{Command: "rm", As: "a\tb"}}}, "run[0]: as must be one line"},
		{"a cancel of nothing", nil, Decision{Cancel: &ComposeCancel{}}, "cancel names nothing"},
		{"a cancel of no key", nil, Decision{Cancel: &ComposeCancel{Keys: []string{""}}}, "keys[0] is empty"},
		{"a timer too short", nil, Decision{After: "500ms"}, "after must be a duration from 1s"},
		{"a timer too long", nil, Decision{After: "25h"}, "after must be a duration from 1s"},
		{"a timer, no duration", nil, Decision{After: "soon"}, "after must be a duration"},
		{"an empty ctx: cleared", nil, Decision{Ctx: &[]byte{}}, ""},
		{"a ctx past its limit", nil, Decision{Ctx: func() *[]byte { b := make([]byte, MaxComposeCtx+1); return &b }()}, "ctx longer than"},
		{"a status on two lines", nil, Decision{Status: text("a\nb")}, "status must be one line"},
		{"a long status", nil, Decision{Status: text(strings.Repeat("s", MaxComposeText+1))}, "status is 1000 bytes at most"},
		{"ok, an err", nil, Decision{Finish: &Finish{OK: true, Err: "no"}}, "an ok finish says a message"},
		{"not ok, silent", nil, Decision{Finish: &Finish{}}, "says why (err)"},
		{"not ok, a message", nil, Decision{Finish: &Finish{Err: "no", Message: "done"}}, "says an err, not a message"},
		{"a long err", nil, Decision{Finish: &Finish{Err: strings.Repeat("e", MaxComposeText+1)}}, "err is 1000 bytes at most"},
		{"out both ways", noOp, Decision{Finish: &Finish{OK: true, Out: []byte("x"), OutFile: subtaskID}}, "not both"},
		{"out too large", noOp, Decision{Finish: &Finish{OK: true, Out: make([]byte, MaxComposeInline+1)}}, "out inline is"},
		{"data, no object", noOp, Decision{Finish: &Finish{OK: true, Data: json.RawMessage(`"x"`)}}, "data must be a JSON object"},
		{"a file id", noOp, Decision{Finish: &Finish{OK: true, DataFile: "data.json"}}, "file ids"},
		{"a subtask's id", noOp, Decision{Finish: &Finish{OK: true, ResultOf: "fetch"}}, "result_of is a subtask's task id"},
		{"a subtask's and its own", noOp, Decision{Finish: &Finish{OK: true, ResultOf: subtaskID, Out: []byte("x")}},
			"gives no out or data of its own"},
		{"the own op, sent", nil, Decision{OwnOp: &OwnOpRun{}}, "it was sent already"},
		{"the own op, none", noOp, Decision{OwnOp: &OwnOpRun{}}, "has no op of its own"},
		{"a cancel of none", noOp, Decision{Cancel: &ComposeCancel{OwnOp: true}}, "has no op of its own"},
		{"a result beside an own op", nil, Decision{Finish: &Finish{OK: true, ResultOf: subtaskID}}, "result is its own op's"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := docRequest(t)
			if tc.call != nil {
				tc.call(&r)
			}
			if err := r.Validate(); err != nil {
				t.Fatalf("the call: %v", err)
			}
			err := tc.d.ValidateFor(r)
			switch {
			case tc.want == "" && err != nil:
				t.Fatal(err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// A decision's ctx and status: absent leaves them, empty clears them.
func TestDecisionLeavesOrClears(t *testing.T) {
	var leaves, clears Decision
	decodeDoc(t, `{}`, &leaves)
	decodeDoc(t, `{"ctx": "", "status": ""}`, &clears)
	switch {
	case leaves.Ctx != nil || leaves.Status != nil:
		t.Fatalf("absent read as given: %+v", leaves)
	case clears.Ctx == nil || len(*clears.Ctx) != 0 || clears.Status == nil || *clears.Status != "":
		t.Fatalf("empty read as absent: %+v", clears)
	}
	raw, err := json.Marshal(clears)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"ctx":"","status":""}` {
		t.Fatalf("written as %s", raw)
	}
	if raw, _ := json.Marshal(leaves); string(raw) != `{}` {
		t.Fatalf("written as %s", raw)
	}
}
