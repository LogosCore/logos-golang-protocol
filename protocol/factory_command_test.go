package protocol

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The examples of the Factory Commands page (docs:
// contracts/factory-commands.md), verbatim: a factory command, a call, an
// output report and a result.
const (
	docFactoryCommands = `{
  "factory_commands": [
    {
      "id": "whois",
      "label": "Who holds the address",
      "description": "Looks the address up in a registry the factory reaches.",
      "params": [
        { "key": "address", "type": "string", "label": "Address", "description": "Empty: the session's external address" }
      ]
    }
  ]
}`

	docFactoryCommandRequest = `{
  "task_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "command": "whois",
  "args": { "address": "" },
  "actor": { "type": "user", "id": "f140266c-…", "name": "admin" },
  "session": {
    "session_id": "1b4e28ba-2fa1-41d2-883f-0016d3cca427",
    "number": 12,
    "operation_id": "6a1f3c0e-2d4b-4e8f-9a7c-5b3d1e0f2a9c",
    "build_id": "5b0c4f6e-8a1d-4c2b-9e7f-3d2a1b0c9e8f",
    "target": "windows-exe",
    "platform": "windows/amd64",
    "description": "Finance workstation",
    "build_description": "Workstations, EU edge",
    "created_at": "2026-11-20T09:12:44Z",
    "last_seen_at": "2026-11-22T14:29:58Z",
    "staged": true,
    "hello": {
      "pid": 4120, "os": "windows", "arch": "amd64", "host": "WS-0042",
      "user": "CORP\\alice", "domain": "CORP", "proc": "svchost.exe", "integrity": "medium",
      "addrs": ["10.1.2.3", "172.17.0.1"], "version": "1.4.0",
      "machine_id": "win-machine-guid:4c4c4544-0042-3510-8052-b4c04f4e3732",
      "x": { "mode": "service" }, "roundtrip_time": 180
    },
    "acting": { "user": "CORP\\svc_backup", "domain": "CORP", "integrity": "high", "how": "impersonation", "since": "2026-11-22T13:02:10Z" },
    "address": "10.1.2.3",
    "peer_address": "203.0.113.7",
    "peers": [{ "address": "203.0.113.7", "first_seen": "2026-11-20T09:12:44Z", "last_seen": "2026-11-22T14:29:58Z", "count": 5120 }],
    "sleep": { "interval": 30000, "jitter": 20 },
    "late_at": "2026-11-22T14:31:04Z",
    "lost_at": "2026-11-22T14:32:16Z",
    "connected": false,
    "conn": 1, "conn_kind": "reverse-call", "conn_name": "edge-eu", "conn_count": 1,
    "max_tasks": 1,
    "feedback_errors": 0,
    "crypto": { "suite": "aes-256-cbc-hmac-sha256", "material": { "enc_key": "…", "mac_key": "…" } }
  },
  "build": {
    "build_id": "5b0c4f6e-8a1d-4c2b-9e7f-3d2a1b0c9e8f",
    "description": "Workstations, EU edge",
    "target": "windows-exe",
    "platform": "windows/amd64",
    "schema_version": 1,
    "created_by": { "type": "user", "id": "f140266c-…", "name": "admin" },
    "created_at": "2026-11-20T09:05:10Z",
    "started_at": "2026-11-20T09:05:11Z",
    "finished_at": "2026-11-20T09:06:02Z",
    "instance": "example-1",
    "factory_version": "0.4.2",
    "request": { "build_id": "5b0c4f6e-8a1d-4c2b-9e7f-3d2a1b0c9e8f", "target": "windows-exe", "platform": "windows/amd64", "schema_version": 1 },
    "connection_descriptions": ["EU edge, through the CDN"],
    "error_codes": [{ "code": 3, "exit_code": 117, "label": "No connection it can use" }],
    "warnings": ["debug build: strings are not obfuscated"],
    "artifact": {
      "filename": "WinTelemetry.exe", "size": 2412544,
      "sha256": "28afe4a10a4a7d593623dcd1eee11f519b056d2bfdda4c7b0bd7a57fc3a5fc8b",
      "media_type": "application/vnd.microsoft.portable-executable",
      "url": "/api/factory/tasks/7c9e6679-7425-40de-944b-e07fc1f90ae7/artifact?sig=…"
    },
    "files": {
      "0f9a2c1e-6f1b-4a43-9d4e-2b9b3c1d7e55": {
        "id": "0f9a2c1e-6f1b-4a43-9d4e-2b9b3c1d7e55", "name": "app.ico", "size": 4286,
        "sha256": "9f2c41d0e5a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2",
        "media_type": "image/x-icon",
        "url": "/api/factory/tasks/7c9e6679-7425-40de-944b-e07fc1f90ae7/build-files/0f9a2c1e-6f1b-4a43-9d4e-2b9b3c1d7e55?sig=…"
      }
    }
  },
  "upload_url": "/api/factory/tasks/7c9e6679-7425-40de-944b-e07fc1f90ae7/files?sig=…"
}`

	docFactoryCommandOutput = `{ "task_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7", "seq": 1, "out": "MjAzLjAuMTEzLjc6IEV4YW1wbGUgTmV0Cg==" }`

	docFactoryCommandResult = `{
  "task_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "state": "done",
  "ok": true,
  "data": { "address": "203.0.113.7", "holder": "Example Net" }
}`
)

// factoryCommandSchema is Minion Build's example schema with the page's
// factory command.
func factoryCommandSchema(t *testing.T) BuildSchema {
	t.Helper()
	s := exampleBuildSchema(t)
	decodeDoc(t, docFactoryCommands, &s)
	return s
}

func docFactoryRequest(t *testing.T) FactoryCommandRequest {
	t.Helper()
	var r FactoryCommandRequest
	decodeDoc(t, docFactoryCommandRequest, &r)
	return r
}

func TestFactoryCommandDocExamples(t *testing.T) {
	s := factoryCommandSchema(t)
	if err := ValidateBuildSchema(s); err != nil {
		t.Fatal(err)
	}
	whois, ok := s.FactoryCommand("whois")
	if !ok || whois.Label != "Who holds the address" || len(whois.Params) != 1 || whois.Params[0].Key != "address" {
		t.Fatalf("factory command decoded: %+v", whois)
	}
	if len(s.Commands) == 0 {
		t.Fatal("the page's factory commands replaced the schema's commands")
	}

	r := docFactoryRequest(t)
	if err := r.ValidateFor(s); err != nil {
		t.Fatal(err)
	}
	ses, b := r.Session, r.Build
	switch {
	case ses.Number != 12 || ses.Hello.Host != "WS-0042" || ses.Hello.User != `CORP\alice` || ses.Hello.X["mode"] != "service":
		t.Fatalf("session decoded: %+v", ses)
	case ses.Acting == nil || ses.Acting.How != "impersonation" || ses.Acting.User != `CORP\svc_backup`:
		t.Fatalf("acting decoded: %+v", ses.Acting)
	case len(ses.Peers) != 1 || ses.Peers[0].Count != 5120 || ses.Sleep == nil || ses.Sleep.Interval != 30000:
		t.Fatalf("peers and sleep decoded: %+v %+v", ses.Peers, ses.Sleep)
	case ses.Crypto == nil || ses.Crypto.Suite != "aes-256-cbc-hmac-sha256" || ses.MaxTasks == nil || *ses.MaxTasks != 1:
		t.Fatalf("crypto and max tasks decoded: %+v", ses)
	case b.Artifact == nil || b.Artifact.Filename != "WinTelemetry.exe" || b.Artifact.Deleted || len(b.Files) != 1:
		t.Fatalf("artifact and files decoded: %+v", b)
	case len(b.ErrorCodes) != 1 || b.ErrorCodes[0].Code != 3 || b.ErrorCodes[0].ExitCode != 117:
		t.Fatalf("error codes decoded: %+v", b.ErrorCodes)
	case b.CreatedBy == nil || b.CreatedBy.Name != "admin" || b.Instance != "example-1":
		t.Fatalf("build decoded: %+v", b)
	}
	if want := time.Date(2026, 11, 22, 14, 31, 4, 0, time.UTC); ses.LateAt == nil || !ses.LateAt.Equal(want) {
		t.Fatalf("late_at = %v, want %v", ses.LateAt, want)
	}
	req, err := b.ReadRequest()
	if err != nil || req.BuildID != b.BuildID || req.Target != "windows-exe" || req.SchemaVersion != 1 {
		t.Fatalf("request read: %+v, %v", req, err)
	}

	var o FactoryCommandOutput
	decodeDoc(t, docFactoryCommandOutput, &o)
	if err := o.Validate(); err != nil {
		t.Fatal(err)
	}
	if o.Seq != 1 || string(o.Out) != "203.0.113.7: Example Net\n" {
		t.Fatalf("output decoded: %d %q", o.Seq, o.Out)
	}

	var res FactoryCommandResult
	decodeDoc(t, docFactoryCommandResult, &res)
	if err := res.Validate(); err != nil {
		t.Fatal(err)
	}
	var data struct {
		Holder string `json:"holder"`
	}
	if res.State != EndDone || !res.OK || json.Unmarshal(res.Data, &data) != nil || data.Holder != "Example Net" {
		t.Fatalf("result decoded: %+v", res)
	}

	reencodes(t, r)
	reencodes(t, o)
	reencodes(t, res)
	reencodes(t, whois)
}

func TestFactoryCommandSchemaChecks(t *testing.T) {
	whois := func(s *BuildSchema) *FactoryCommand { return &s.FactoryCommands[0] }
	file := FieldSpec{Key: "doc", Type: FieldFile, Label: "Document", Accept: []string{".pdf"}, MaxSize: 1 << 20}
	cases := []struct {
		name string
		edit func(s *BuildSchema)
		want string // "": valid
	}{
		{"the page's", func(*BuildSchema) {}, ""},
		{"none", func(s *BuildSchema) { s.FactoryCommands = nil }, ""},
		{"a result", func(s *BuildSchema) { whois(s).Result = ResultDirListing }, ""},
		{"a file and a credential", func(s *BuildSchema) {
			whois(s).Params = append(whois(s).Params, file, FieldSpec{Key: "login", Type: FieldCredential, Label: "Login"})
		}, ""},
		{"a param by condition", func(s *BuildSchema) {
			whois(s).Params = append(whois(s).Params,
				FieldSpec{Key: "registry", Type: FieldEnum, Label: "Registry", Default: "arin",
					Options: []EnumOption{{Value: "arin", Label: "ARIN"}, {Value: "ripe", Label: "RIPE"}}},
				FieldSpec{Key: "deep", Type: FieldBool, Label: "Deep", When: &FieldCondition{Key: "registry", Values: []string{"ripe"}}})
		}, ""},
		{"a command's id", func(s *BuildSchema) { whois(s).ID = "shell" }, "a command of the schema has its id"},
		{"twice", func(s *BuildSchema) { s.FactoryCommands = append(s.FactoryCommands, *whois(s)) }, `duplicate factory command "whois"`},
		{"core's own", func(s *BuildSchema) { whois(s).ID = CommandHelp }, "core's own command"},
		{"a bad id", func(s *BuildSchema) { whois(s).ID = "Whois" }, "id must match"},
		{"a num", func(s *BuildSchema) { whois(s).Params[0].Num = 1 }, "numbers no params"},
		{"a stream", func(s *BuildSchema) {
			whois(s).Params = append(whois(s).Params, FieldSpec{Key: "feed", Type: FieldStream, Label: "Feed"})
		}, "takes no stream"},
		{"two files", func(s *BuildSchema) {
			second := file
			second.Key = "doc2"
			whois(s).Params = append(whois(s).Params, file, second)
		}, "one file param at most"},
		{"a param twice", func(s *BuildSchema) { whois(s).Params = append(whois(s).Params, whois(s).Params[0]) }, `duplicate param "address"`},
		{"a bad param", func(s *BuildSchema) { whois(s).Params[0].Type = "nope" }, `param "address": invalid type`},
		{"an unknown result", func(s *BuildSchema) { whois(s).Result = "nope" }, `result "nope" is not one core knows`},
		{"a condition on nothing", func(s *BuildSchema) {
			whois(s).Params[0].When = &FieldCondition{Key: "missing", Values: []string{"x"}}
		}, `"missing" is no param of the form`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := factoryCommandSchema(t)
			tc.edit(&s)
			err := ValidateBuildSchema(s)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestSessionFactoryCommands(t *testing.T) {
	s := factoryCommandSchema(t)
	s.FactoryCommands = append(s.FactoryCommands, FactoryCommand{ID: "decode", Label: "Decode a capture"})
	ids := func(cs []FactoryCommand) []string {
		out := []string{}
		for _, c := range cs {
			out = append(out, c.ID)
		}
		return out
	}
	// A build whose schema version had its own whois keeps it: the
	// factory's comes after, for the sessions of builds without one.
	for _, tc := range []struct {
		session []string
		want    []string
	}{
		{[]string{"sleep", "exit"}, []string{"whois", "decode"}},
		{[]string{"sleep", "whois"}, []string{"decode"}},
		{nil, []string{"whois", "decode"}},
	} {
		if got := ids(s.SessionFactoryCommands(tc.session)); !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("session %v: %v, want %v", tc.session, got, tc.want)
		}
	}
	if _, ok := s.FactoryCommand("shell"); ok {
		t.Fatal("a build's command found among the factory commands")
	}
}

func TestFactoryCommandArgs(t *testing.T) {
	c := FactoryCommand{ID: "lookup", Params: []FieldSpec{
		{Key: "address", Type: FieldString, Label: "Address", Required: true},
		{Key: "depth", Type: FieldInt, Label: "Depth", Default: float64(2)},
	}}
	args, problems := c.Args(map[string]any{"address": "203.0.113.7"})
	if problems != nil || !reflect.DeepEqual(args, map[string]any{"address": "203.0.113.7", "depth": float64(2)}) {
		t.Fatalf("args %v, problems %v", args, problems)
	}
	if _, problems := c.Args(map[string]any{"depth": float64(3)}); problems["address"] == "" {
		t.Fatalf("a required param left out: problems %v", problems)
	}
	if _, problems := c.Args(map[string]any{"address": "x", "port": float64(1)}); problems["port"] == "" {
		t.Fatalf("an undeclared arg: problems %v", problems)
	}
}

func TestFactoryCommandRequestChecks(t *testing.T) {
	cases := []struct {
		name string
		edit func(r *FactoryCommandRequest)
		want string // "": valid
	}{
		{"the page's", func(*FactoryCommandRequest) {}, ""},
		{"a session never seen, with no hello host", func(r *FactoryCommandRequest) {
			r.Session.LastSeenAt, r.Session.Hello.Host, r.Session.Acting, r.Session.Crypto = nil, "", nil, nil
		}, ""},
		{"a deleted artifact", func(r *FactoryCommandRequest) { r.Build.Artifact.Deleted, r.Build.Artifact.URL = true, "" }, ""},
		{"a bad task id", func(r *FactoryCommandRequest) { r.TaskID = "7C9E" }, "task_id must be a lowercase UUID"},
		{"a bad command", func(r *FactoryCommandRequest) { r.Command = "Whois" }, "command must match"},
		{"no upload link", func(r *FactoryCommandRequest) { r.UploadURL = "files" }, "upload_url must be a link"},
		{"another build's session", func(r *FactoryCommandRequest) {
			r.Session.BuildID = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
		}, "are its build's"},
		{"another target", func(r *FactoryCommandRequest) { r.Session.Target = "linux-elf" }, "are its build's"},
		{"no number", func(r *FactoryCommandRequest) { r.Session.Number = 0 }, "session: number counts from 1"},
		{"no hello os", func(r *FactoryCommandRequest) { r.Session.Hello.OS = "" }, "os and arch are required"},
		{"an address that is none", func(r *FactoryCommandRequest) {
			r.Session.Hello.Addrs = []string{"WS-0042"}
		}, "addrs[0] is not an IP address"},
		{"acting with no user", func(r *FactoryCommandRequest) { r.Session.Acting.User = "" }, "acting: user and since"},
		{"a jitter over 100", func(r *FactoryCommandRequest) { r.Session.Sleep.Jitter = 101 }, "jitter a percent"},
		{"a bad via", func(r *FactoryCommandRequest) {
			r.Session.Via = []SessionVia{{SessionID: "x", Number: 1, TaskID: "y"}}
		}, "via[0]"},
		{"a connection of no kind", func(r *FactoryCommandRequest) {
			r.Session.Connections = []SessionConnection{{Channel: "http", Kind: "carrier-pigeon", Name: "edge-eu"}}
		}, `kind "carrier-pigeon"`},
		{"a restart of no build", func(r *FactoryCommandRequest) {
			r.Session.Restarts = []SessionRestart{{At: time.Now(), PID: 7, BuildID: "nope"}}
		}, "restarts[0]"},
		{"another build's request", func(r *FactoryCommandRequest) {
			r.Build.Request = json.RawMessage(`{"build_id":"3f2504e0-4f89-41d3-9a0c-0305e82c3301"}`)
		}, "request is another build's"},
		{"a request that is no object", func(r *FactoryCommandRequest) { r.Build.Request = json.RawMessage(`[1]`) },
			"request must be the factory.build payload"},
		{"no request", func(r *FactoryCommandRequest) { r.Build.Request = nil }, "request must be the factory.build payload"},
		{"a deleted artifact with a link", func(r *FactoryCommandRequest) { r.Build.Artifact.Deleted = true },
			"one deleted has no url"},
		{"an artifact with no link", func(r *FactoryCommandRequest) { r.Build.Artifact.URL = "" }, "artifact: url must be a link"},
		{"an exit code past 255", func(r *FactoryCommandRequest) { r.Build.ErrorCodes[0].ExitCode = 256 },
			"error_codes[0]: code and exit_code are 1 to 255"},
		{"a build file under another id", func(r *FactoryCommandRequest) {
			f := r.Build.Files["0f9a2c1e-6f1b-4a43-9d4e-2b9b3c1d7e55"]
			r.Build.Files = map[string]BuildFile{"3f2504e0-4f89-41d3-9a0c-0305e82c3301": f}
		}, "does not match its key"},
		{"a credential under another id", func(r *FactoryCommandRequest) {
			r.Credentials = map[string]Credential{"3f2504e0-4f89-41d3-9a0c-0305e82c3301": {
				ID: "d4f9a1c2-5b3e-4c7d-8e9f-0a1b2c3d4e5f", Type: CredentialTypePlaintext, Username: "alice", Password: "s3cret"}}
		}, "credentials: credential d4f9a1c2"},
		{"not a factory command", func(r *FactoryCommandRequest) { r.Command = "shell" }, `"shell" is not one of the factory's factory commands`},
		{"an arg undeclared", func(r *FactoryCommandRequest) { r.Args["port"] = float64(43) }, "args: port: not a declared field"},
	}
	s := factoryCommandSchema(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := docFactoryRequest(t)
			tc.edit(&r)
			err := r.ValidateFor(s)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// A factory command's file and credential params name what the call gives
// by id, as a build request's values do.
func TestFactoryCommandRequestFilesAndCredentials(t *testing.T) {
	const fileID, credID = "d4f9a1c2-5b3e-4c7d-8e9f-0a1b2c3d4e5f", "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
	s := factoryCommandSchema(t)
	s.FactoryCommands = append(s.FactoryCommands, FactoryCommand{ID: "decode", Label: "Decode a capture", Params: []FieldSpec{
		{Key: "capture", Type: FieldFile, Label: "Capture", Accept: []string{".pcap"}, Required: true},
		{Key: "login", Type: FieldCredential, Label: "Login", Accept: []string{CredentialTypePlaintext}},
	}})
	if err := ValidateBuildSchema(s); err != nil {
		t.Fatal(err)
	}
	good := func(t *testing.T) FactoryCommandRequest {
		t.Helper()
		r := docFactoryRequest(t)
		r.Command, r.Args = "decode", map[string]any{"capture": fileID, "login": credID}
		r.Files = map[string]BuildFile{fileID: {ID: fileID, Name: "edge.pcap", Size: 81920,
			SHA256: "63af51616216a711fb32172e019b127a511e67e1603563840de4724e1d60c9ff",
			URL:    "/api/factory/tasks/7c9e6679-7425-40de-944b-e07fc1f90ae7/files/" + fileID + "?sig=…"}}
		r.Credentials = map[string]Credential{credID: {ID: credID, Type: CredentialTypePlaintext, Username: "alice", Password: "s3cret"}}
		return r
	}
	r := good(t)
	if err := r.ValidateFor(s); err != nil {
		t.Fatal(err)
	}
	reencodes(t, r)

	for _, tc := range []struct {
		name string
		edit func(r *FactoryCommandRequest)
		want string
	}{
		{"the file not given", func(r *FactoryCommandRequest) { r.Files = nil }, `args: capture: file "` + fileID + `" is not in files`},
		{"a file the param does not take", func(r *FactoryCommandRequest) {
			f := r.Files[fileID]
			f.Name = "edge.txt"
			r.Files[fileID] = f
		}, "args: capture: must be one of: .pcap"},
		{"the credential not given", func(r *FactoryCommandRequest) { r.Credentials = nil }, "args: login:"},
		{"a credential the param does not take", func(r *FactoryCommandRequest) {
			r.Credentials[credID] = Credential{ID: credID, Type: CredentialTypeKey, Key: "k"}
		}, "args: login:"},
		{"the file arg left out", func(r *FactoryCommandRequest) { delete(r.Args, "capture") }, "args: capture: value is required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := good(t)
			tc.edit(&r)
			if err := r.ValidateFor(s); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestFactoryCommandResultChecks(t *testing.T) {
	const task, file = "7c9e6679-7425-40de-944b-e07fc1f90ae7", "d4f9a1c2-5b3e-4c7d-8e9f-0a1b2c3d4e5f"
	exit := int64(3)
	big := json.RawMessage(`{"blob":"` + strings.Repeat("a", MaxFactoryCommandInline) + `"}`)
	cases := []struct {
		name string
		r    FactoryCommandResult
		want string // "": valid
	}{
		{"done, ok", FactoryCommandResult{TaskID: task, State: EndDone, OK: true}, ""},
		{"done, not ok, with an exit and err", FactoryCommandResult{TaskID: task, State: EndDone, Err: "registry said no", Exit: &exit}, ""},
		{"done, data as a file, and files", FactoryCommandResult{TaskID: task, State: EndDone, OK: true, DataFile: file, Files: []string{file}}, ""},
		{"failed", FactoryCommandResult{TaskID: task, State: EndFailed, Err: "the registry cannot be reached"}, ""},
		{"no state", FactoryCommandResult{TaskID: task}, "state must be"},
		{"cancelled", FactoryCommandResult{TaskID: task, State: EndCancelled}, "state must be"},
		{"a bad task id", FactoryCommandResult{TaskID: "x", State: EndDone}, "task_id must be a lowercase UUID"},
		{"failed, no err", FactoryCommandResult{TaskID: task, State: EndFailed}, "says why"},
		{"failed, ok", FactoryCommandResult{TaskID: task, State: EndFailed, OK: true, Err: "x"}, "returns nothing"},
		{"failed, with data", FactoryCommandResult{TaskID: task, State: EndFailed, Err: "x", Data: json.RawMessage(`{}`)}, "returns nothing"},
		{"ok with an err", FactoryCommandResult{TaskID: task, State: EndDone, OK: true, Err: "x"}, "an ok task has no err"},
		{"data both ways", FactoryCommandResult{TaskID: task, State: EndDone, Data: json.RawMessage(`{}`), DataFile: file}, "not both"},
		{"data too large", FactoryCommandResult{TaskID: task, State: EndDone, Data: big}, "data inline is 16384 bytes at most"},
		{"data no object", FactoryCommandResult{TaskID: task, State: EndDone, Data: json.RawMessage(`[1]`)}, "a JSON object"},
		{"a bad data file", FactoryCommandResult{TaskID: task, State: EndDone, DataFile: "f"}, "data_file is a file id"},
		{"a file twice", FactoryCommandResult{TaskID: task, State: EndDone, Files: []string{file, file}}, "named twice"},
		{"a bad file", FactoryCommandResult{TaskID: task, State: EndDone, Files: []string{"f"}}, "files[0] is a file id"},
		{"too many files", FactoryCommandResult{TaskID: task, State: EndDone, Files: make([]string, MaxFactoryCommandFiles+1)}, "too many files"},
		{"a long err", FactoryCommandResult{TaskID: task, State: EndFailed, Err: strings.Repeat("e", MaxComposeText+1)}, "err is 1000 bytes at most"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.r.Validate()
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestFactoryCommandReports(t *testing.T) {
	const task = "7c9e6679-7425-40de-944b-e07fc1f90ae7"
	for _, tc := range []struct {
		name string
		err  error
		want string // "": valid
	}{
		{"output, still running", FactoryCommandOutput{TaskID: task, Seq: 7}.Validate(), ""},
		{"output, seq 0", FactoryCommandOutput{TaskID: task}.Validate(), "seq counts from 1"},
		{"output, too long", FactoryCommandOutput{TaskID: task, Seq: 1, Out: make([]byte, MaxFactoryCommandOut+1)}.Validate(),
			"out is 16384 bytes at most"},
		{"output, a bad task", FactoryCommandOutput{TaskID: "x", Seq: 1}.Validate(), "task_id"},
		{"accepted", FactoryCommandReply{TaskID: task, Accepted: true}.Validate(), ""},
		{"not accepted", FactoryCommandReply{TaskID: task}.Validate(), "replies with an error"},
		{"a cancel", FactoryCommandCancelRequest{TaskID: task}.Validate(), ""},
		{"a cancel of no task", FactoryCommandCancelRequest{}.Validate(), "task_id"},
	} {
		switch {
		case tc.want == "" && tc.err != nil:
			t.Errorf("%s: refused: %v", tc.name, tc.err)
		case tc.want != "" && (tc.err == nil || !strings.Contains(tc.err.Error(), tc.want)):
			t.Errorf("%s: err = %v, want %q", tc.name, tc.err, tc.want)
		}
	}
}
