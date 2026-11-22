package protocol

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// Factory commands (docs: contracts/factory-commands.md). A factory may
// declare commands it runs itself, in the factory module, never on a minion
// (BuildSchema.FactoryCommands): every session of every build it made has
// them, minions already deployed among them; no build picks one, and no
// minion carries one. Their tasks are the session's, kept with its other
// tasks.
//
// Core offers a task to an instance of the session's factory kind whose
// schema declares the command (TypeFactoryCommand), with everything it keeps
// of the session (SessionRecord) and of its build (BuildRecord, the
// factory.build request among it). The instance that accepts it reports what
// the command prints (TypeFactoryCommandOutput) and how it ended
// (TypeFactoryCommandResult); core stops it with TypeFactoryCommandCancel. As
// a build's, all four are request/reply.

// Factory command operation types.
const (
	TypeFactoryCommand       = "factory.command"        // core → factory
	TypeFactoryCommandCancel = "factory.command.cancel" // core → factory
	TypeFactoryCommandOutput = "factory.command.output" // factory → core
	TypeFactoryCommandResult = "factory.command.result" // factory → core
)

// Factory command limits.
const (
	// MaxFactoryCommandOut bounds an output report's out, in bytes.
	MaxFactoryCommandOut = 16 << 10
	// MaxFactoryCommandInline bounds a result's data inline (its JSON), in
	// bytes: larger goes as a file the factory put for the task.
	MaxFactoryCommandInline = 16 << 10
	// MaxFactoryCommandFiles bounds the files a result names.
	MaxFactoryCommandFiles = 32
	// FactoryCommandNoReport is how long core waits for a report (output or
	// result) from the instance running a task: past it the task ends
	// failed, and core asks the factory to stop it. An output report with
	// nothing printed says the command still runs.
	FactoryCommandNoReport = 10 * time.Minute
)

// FactoryCommand is a command its factory runs itself
// (BuildSchema.FactoryCommands). A session has those of its factory kind's
// latest schema, whatever its build's target, commands and schema version,
// but one whose id its build's commands have (SessionFactoryCommands). It has
// nothing a command has for its minion: no op, targets, default, required,
// legacy, kinds, opens, serves, action, composite or uses.
type FactoryCommand struct {
	// ID names it in the console, core and the APIs: a command's pattern,
	// unique among the schema's commands and factory commands, and none of
	// core's own.
	ID          string `json:"id"`
	Label       string `json:"label,omitempty"`
	Description string `json:"description,omitempty"`
	// Params are what a task of it takes: field specs as a command's, with
	// no num (nothing of it goes to a minion) and no stream, one file param
	// at most. A task's args name a file param's file, and a credential
	// param's credentials, by id (FactoryCommandRequest.Files, .Credentials).
	Params []FieldSpec `json:"params,omitempty"`
	// Result is what its task's data is: one of core's results; empty: no
	// declared shape, shown raw.
	Result string `json:"result,omitempty"`
}

// FactoryCommand returns the factory command with id, if declared.
func (s BuildSchema) FactoryCommand(id string) (FactoryCommand, bool) {
	for _, c := range s.FactoryCommands {
		if c.ID == id {
			return c, true
		}
	}
	return FactoryCommand{}, false
}

// SessionFactoryCommands returns the factory commands a session has, s being
// its factory kind's latest schema and session what the session's build gives
// it to run (SessionCommands, in the build's own schema version): every one of
// s's, in its order, but those whose id is one of session's, which come first.
func (s BuildSchema) SessionFactoryCommands(session []string) []FactoryCommand {
	out := []FactoryCommand{}
	for _, c := range s.FactoryCommands {
		if !slices.Contains(session, c.ID) {
			out = append(out, c)
		}
	}
	return out
}

// Args checks values against the command's params and returns its task's
// args: the values over the params' defaults, as JSON values (what the call
// carries). Problems come by param key, as ValidateFieldValues reports them;
// with any, args is nil.
func (c FactoryCommand) Args(values map[string]any) (map[string]any, map[string]string) {
	if problems := ValidateFieldValues(c.Params, values); problems != nil {
		return nil, problems
	}
	args := ResolveFieldValues(c.Params, values)
	var problems map[string]string
	for _, f := range c.Params {
		// A default is checked here: ValidateFieldValues sees only values.
		if v, ok := args[f.Key]; ok {
			if err := ValidateValue(f, v); err != nil {
				problems = addProblem(problems, f.Key, err.Error())
			}
		}
	}
	if problems != nil {
		return nil, problems
	}
	return args, nil
}

// validateFactoryCommands checks a schema's factory commands: each id a
// command's pattern and its own (no command's, no other factory command's,
// none of core's), a known result, and params as a command's with no num and
// no stream, one file at most.
func validateFactoryCommands(s BuildSchema) error {
	if len(s.FactoryCommands) > MaxBuildCommands {
		return fmt.Errorf("too many factory commands (%d > %d)", len(s.FactoryCommands), MaxBuildCommands)
	}
	for i, c := range s.FactoryCommands {
		if err := validateFactoryCommand(c); err != nil {
			return fmt.Errorf("factory command %q: %w", c.ID, err)
		}
		if _, ok := s.Command(c.ID); ok {
			return fmt.Errorf("factory command %q: a command of the schema has its id, and a session names each by it", c.ID)
		}
		if slices.ContainsFunc(s.FactoryCommands[:i], func(o FactoryCommand) bool { return o.ID == c.ID }) {
			return fmt.Errorf("duplicate factory command %q", c.ID)
		}
	}
	return nil
}

func validateFactoryCommand(c FactoryCommand) error {
	switch {
	case !commandIDPattern.MatchString(c.ID):
		return fmt.Errorf("id must match %s", commandIDPattern)
	case IsCoreCommand(c.ID):
		return fmt.Errorf("%q is core's own command: a factory does not declare it", c.ID)
	case c.Result != "" && !KnownResult(c.Result):
		return fmt.Errorf("result %q is not one core knows (%s)", c.Result, strings.Join(keysOf(results), ", "))
	case len(c.Params) > MaxCommandParams:
		return fmt.Errorf("too many params (%d > %d)", len(c.Params), MaxCommandParams)
	}
	if err := validateText(c.Label, c.Description); err != nil {
		return err
	}
	keys := make(map[string]bool, len(c.Params))
	files := 0
	for _, p := range c.Params {
		switch {
		case p.Num != 0:
			return fmt.Errorf("param %q: a factory command numbers no params: nothing of it goes to a minion", p.Key)
		case p.Type == FieldStream:
			return fmt.Errorf("param %q: a factory command takes no stream: a stream feeds a minion's task", p.Key)
		}
		if err := checkCommandParam(p); err != nil {
			return fmt.Errorf("param %q: %w", p.Key, err)
		}
		if keys[p.Key] {
			return fmt.Errorf("duplicate param %q", p.Key)
		}
		keys[p.Key] = true
		if p.Type == FieldFile {
			if files++; files > 1 {
				return fmt.Errorf("param %q: a factory command takes one file param at most", p.Key)
			}
		}
	}
	return validateParamConditions(c.Params, nil)
}

// FactoryCommandRequest is the factory.command payload: a task to run, with
// everything core keeps of its session and of the session's build. Its
// secrets (the session's keys; the build request's keys and credentials; the
// task's credentials) are for the task alone: a factory does not log them,
// keep them past the task, or put them in its output, data or files.
type FactoryCommandRequest struct {
	TaskID string `json:"task_id"`
	// Command is the factory command, by id; Args its args by param key,
	// defaults filled in. A file param's arg is the file's id, a credential
	// param's the credential's (a credential list's, their ids).
	Command string         `json:"command"`
	Args    map[string]any `json:"args,omitempty"`
	// Actor is who queued the task, as a build's.
	Actor *Actor `json:"actor,omitempty"`
	// Session is the task's session, Build its build.
	Session SessionRecord `json:"session"`
	Build   BuildRecord   `json:"build"`
	// Files are the files the args name, by id, each with a link to fetch
	// it whole.
	Files map[string]BuildFile `json:"files,omitempty"`
	// Credentials are the credentials the args name, by id, with their
	// secrets.
	Credentials map[string]Credential `json:"credentials,omitempty"`
	// UploadURL is where the factory puts a file for the task (a link): a
	// PUT of the whole, with its Content-Length and its name
	// (HeaderFileName), as a composite's code does (ComposeRequest).
	UploadURL string `json:"upload_url"`
}

// FactoryCommandReply is the factory.command reply payload: the instance
// accepted the task and runs it. One that does not take it replies with an
// error instead: CodeBusy (core offers it to another), or another code (the
// task ends failed with its message).
type FactoryCommandReply struct {
	TaskID   string `json:"task_id"`
	Accepted bool   `json:"accepted"`
}

// SessionRecord is a session as core keeps it, with its keys: what a factory
// command's call carries of its session. Core's bookkeeping, its copies of
// its build's fields (BuildRecord says them) and the keys of processes a
// claim replaced are not in it. A field core has no value for is absent.
type SessionRecord struct {
	SessionID string `json:"session_id"`
	// Number is the session's in its operation, what operators call it.
	Number      int64  `json:"number"`
	OperationID string `json:"operation_id"`
	// BuildID, Target and Platform are its build's.
	BuildID  string `json:"build_id"`
	Target   string `json:"target"`
	Platform string `json:"platform"`
	// Description is what it is for, the operators' note; BuildDescription
	// its build's when it opened.
	Description      string `json:"description,omitempty"`
	BuildDescription string `json:"build_description,omitempty"`
	// CreatedAt is when it opened, LastSeenAt its latest message: nil
	// before its first check-in.
	CreatedAt  time.Time  `json:"created_at"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
	// Staged: opened under a temporary id after a stage, not straight under
	// the build id.
	Staged bool         `json:"staged"`
	Hello  SessionHello `json:"hello"`
	// Acting is who its tasks run as when not the process's own.
	Acting *SessionIdentity `json:"acting,omitempty"`
	// Address is the one of Hello.Addrs the session shows: an operator's
	// pick, else core's guess at the host's real one.
	Address string `json:"address,omitempty"`
	// PeerAddress is its external address now, Peers each one it was seen
	// from, most recent first.
	PeerAddress string        `json:"peer_address,omitempty"`
	Peers       []SessionPeer `json:"peers,omitempty"`
	// Via are the delegates its messages come through, nearest first, and
	// ViaSince since when.
	Via      []SessionVia `json:"via,omitempty"`
	ViaSince *time.Time   `json:"via_since,omitempty"`
	// Sleep is the check-in schedule its minion said; LateAt and LostAt are
	// when the session turns late and lost by it.
	Sleep  *SessionSleep `json:"sleep,omitempty"`
	LateAt *time.Time    `json:"late_at,omitempty"`
	LostAt *time.Time    `json:"lost_at,omitempty"`
	// Connected: a persistent connection serving it is open.
	Connected bool `json:"connected"`
	// Conn is the connection its minion uses, its place from 1, ConnKind and
	// ConnName that connection's, ConnCount how many it has, and ConnChanges
	// the moves the minion reported, most recent first.
	Conn        int                 `json:"conn,omitempty"`
	ConnKind    string              `json:"conn_kind,omitempty"`
	ConnName    string              `json:"conn_name,omitempty"`
	ConnCount   int                 `json:"conn_count,omitempty"`
	ConnChanges []SessionConnChange `json:"conn_changes,omitempty"`
	// Connections are the minion's own, when its hello said them (Conn is a
	// place in them then), and ConnectionsAt when they last changed; nil:
	// its build's.
	Connections   []SessionConnection `json:"connections,omitempty"`
	ConnectionsAt *time.Time          `json:"connections_at,omitempty"`
	// MaxTasks is how many tasks its minion runs at once, as it said;
	// MaxTasksSet the operators' limit.
	MaxTasks    *int `json:"max_tasks,omitempty"`
	MaxTasksSet *int `json:"max_tasks_set,omitempty"`
	// FeedbackErrors are its unread errors, FeedbackAt when its latest
	// feedback came, FeedbackReadAt when someone last marked it read.
	FeedbackErrors int        `json:"feedback_errors"`
	FeedbackAt     *time.Time `json:"feedback_at,omitempty"`
	FeedbackReadAt *time.Time `json:"feedback_read_at,omitempty"`
	// Persisted: a build names the session, and its minions claim it.
	// Restarts are the latest claims, most recent first, RestartCount all of
	// them.
	Persisted    bool             `json:"persisted,omitempty"`
	Restarts     []SessionRestart `json:"restarts,omitempty"`
	RestartCount int64            `json:"restart_count,omitempty"`
	// Archived hides it from the operation's sessions; FolderID is the
	// operation's folder it is in.
	Archived bool   `json:"archived,omitempty"`
	FolderID string `json:"folder_id,omitempty"`
	// Crypto is its suite and key material: what its minion's messages are
	// sealed with now.
	Crypto *BuildCrypto `json:"crypto,omitempty"`
}

// SessionHello is what a session's latest hello said (HelloItem), as core
// keeps it: Proc as the process's name, Integrity by name (IntegrityName),
// Addrs as text, MachineID as "<source>:<value>" (MachineID), RoundtripTime in
// milliseconds.
type SessionHello struct {
	PID           uint64         `json:"pid,omitempty"`
	OS            string         `json:"os"`
	Arch          string         `json:"arch"`
	Host          string         `json:"host,omitempty"`
	User          string         `json:"user,omitempty"`
	Domain        string         `json:"domain,omitempty"`
	Proc          string         `json:"proc,omitempty"`
	Integrity     string         `json:"integrity,omitempty"`
	Addrs         []string       `json:"addrs,omitempty"`
	Version       string         `json:"version,omitempty"`
	MachineID     string         `json:"machine_id,omitempty"`
	X             map[string]any `json:"x,omitempty"`
	RoundtripTime *int           `json:"roundtrip_time,omitempty"`
}

// SessionIdentity is who a session's tasks run as when not its process's own
// (IdentityItem): How by name (IdentityHowName), CredentialID the credential
// it took when a task's did, TaskID the task that made it.
type SessionIdentity struct {
	User         string    `json:"user,omitempty"`
	Domain       string    `json:"domain,omitempty"`
	Integrity    string    `json:"integrity,omitempty"`
	How          string    `json:"how,omitempty"`
	CredentialID string    `json:"credential_id,omitempty"`
	TaskID       string    `json:"task_id,omitempty"`
	Since        time.Time `json:"since"`
}

// SessionPeer is an external address a session was seen from, and Count its
// messages from it.
type SessionPeer struct {
	Address   string    `json:"address"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count     int64     `json:"count"`
}

// SessionVia is a delegate on a session's way to core: the session whose task
// (TaskID) carried its messages, and its number.
type SessionVia struct {
	SessionID string `json:"session_id"`
	Number    int64  `json:"number"`
	TaskID    string `json:"task_id"`
}

// SessionSleep is a minion's check-in schedule: Interval milliseconds between
// check-ins, spread by Jitter percent of it either way.
type SessionSleep struct {
	Interval int64 `json:"interval"`
	Jitter   int64 `json:"jitter"`
}

// SessionConnChange is a move to another connection a minion reported: from
// the place it used (0: unknown) to To, and why, when it said.
type SessionConnChange struct {
	At     time.Time `json:"at"`
	From   int       `json:"from,omitempty"`
	To     int       `json:"to"`
	Reason string    `json:"reason,omitempty"`
}

// SessionConnection is one of the connections a session's minion said in its
// hello (HelloConnection), as core keeps it: Params and Values by their
// fields' numbers, as text.
type SessionConnection struct {
	Channel      string         `json:"channel"`
	Kind         string         `json:"kind"`
	Name         string         `json:"name"`
	Version      uint64         `json:"version,omitempty"`
	Params       map[string]any `json:"params,omitempty"`
	Values       map[string]any `json:"values,omitempty"`
	FailoverAuto *bool          `json:"failover_auto,omitempty"`
	FailAfter    uint64         `json:"fail_after,omitempty"`
	MaxMessage   int            `json:"max_message,omitempty"`
}

// SessionRestart is a claim that brought a process into a persisted session.
type SessionRestart struct {
	At      time.Time `json:"at"`
	PID     uint64    `json:"pid"`
	Host    string    `json:"host,omitempty"`
	BuildID string    `json:"build_id"`
}

// BuildRecord is a build as core keeps it: core's record, and the
// factory.build request its factory got. What a factory command's call
// carries of its session's build. The build's plan, step reports and log are
// not in it.
type BuildRecord struct {
	BuildID string `json:"build_id"`
	// Description is what it is for, the operators' note: core's own, never
	// in the request.
	Description   string `json:"description,omitempty"`
	Target        string `json:"target"`
	Platform      string `json:"platform"`
	SchemaVersion int    `json:"schema_version"`
	// CreatedBy started it at CreatedAt; StartedAt is when an instance took
	// it, FinishedAt when it ended.
	CreatedBy  *Actor     `json:"created_by,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	// Instance built it, at FactoryVersion.
	Instance       string `json:"instance,omitempty"`
	FactoryVersion string `json:"factory_version,omitempty"`
	// Request is the factory.build payload Instance got (a BuildRequest),
	// byte for byte: its links have expired, Files and Artifact carry new
	// ones. ReadRequest reads it.
	Request json.RawMessage `json:"request"`
	// ConnectionDescriptions are the operators' notes on its connections,
	// by place ("" for none): core's own.
	ConnectionDescriptions []string `json:"connection_descriptions,omitempty"`
	// ErrorCodes are what its minion's exit codes mean: each its factory
	// declared, with the code this build's minion exits with for it.
	ErrorCodes []BuildRecordErrorCode `json:"error_codes,omitempty"`
	// CredentialRevs are the revisions of the credentials the request
	// carries, by id.
	CredentialRevs map[string]int64 `json:"credential_revs,omitempty"`
	// Codec is what the factory declared of the layers it translates, for a
	// build whose suite or envelope is its own.
	Codec    *BuildCodec          `json:"codec,omitempty"`
	Warnings []string             `json:"warnings,omitempty"`
	Artifact *BuildRecordArtifact `json:"artifact,omitempty"`
	// Files are the build files its values name, by id, each with a new
	// link.
	Files map[string]BuildFile `json:"files,omitempty"`
}

// BuildRecordErrorCode is one of a build's error codes: its factory's
// (ErrorCode), with ExitCode, what the build's minion exits with for it
// (drawn for the build, or Code).
type BuildRecordErrorCode struct {
	ErrorCode
	ExitCode int `json:"exit_code"`
}

// BuildRecordArtifact is a build's artifact as core keeps it: what its factory
// reported, with a link to fetch it, or Deleted, and no link, once an
// operator removed its bytes.
type BuildRecordArtifact struct {
	BuildArtifact
	URL     string `json:"url,omitempty"`
	Deleted bool   `json:"deleted,omitempty"`
}

// ReadRequest reads the build's request: the factory.build payload its
// factory got. Its links have expired: the record's Files and Artifact carry
// new ones.
func (b BuildRecord) ReadRequest() (BuildRequest, error) {
	var r BuildRequest
	if err := json.Unmarshal(b.Request, &r); err != nil {
		return BuildRequest{}, fmt.Errorf("request: %w", err)
	}
	return r, nil
}

// FactoryCommandOutput is the factory.command.output payload: what a task's
// command printed since the last report.
type FactoryCommandOutput struct {
	TaskID string `json:"task_id"`
	// Seq numbers the reports from 1, one more each. They go one at a time,
	// in order: one whose reply was lost goes again with the same Seq, and
	// core keeps it once.
	Seq int64 `json:"seq"`
	// Out is what was printed, MaxFactoryCommandOut bytes at most (base64 in
	// JSON); none says the command still runs.
	Out []byte `json:"out,omitempty"`
}

// FactoryCommandOutputReply is the factory.command.output reply payload. Core
// replies CodeNotFound instead when it no longer waits for the task from this
// instance (it was stopped, or is another's), and the factory stops it.
type FactoryCommandOutputReply struct {
	TaskID string `json:"task_id"`
	Seq    int64  `json:"seq"`
	Ack    bool   `json:"ack"`
}

// FactoryCommandResult is the factory.command.result payload: how a task
// ended. The factory sends what is left of its output first, and the result
// again until core replies.
type FactoryCommandResult struct {
	TaskID string `json:"task_id"`
	// State is EndDone, the command ran (OK, Err and Exit say how, as a
	// minion's last result part does), or EndFailed, the factory could not
	// run it (Err says why), with nothing returned.
	State EndState `json:"state"`
	OK    bool     `json:"ok"`
	Err   string   `json:"err,omitempty"`
	Exit  *int64   `json:"exit,omitempty"`
	// Data is the task's data, a JSON object in the command's result's
	// shape: inline up to MaxFactoryCommandInline bytes, or as a file the
	// factory put for the task (DataFile, its id), which core takes as the
	// data and drops.
	Data     json.RawMessage `json:"data,omitempty"`
	DataFile string          `json:"data_file,omitempty"`
	// Files are the ids of files the factory put that are the task's own (a
	// decoded document, a report), which the task lists.
	Files []string `json:"files,omitempty"`
}

// FactoryCommandResultReply is the factory.command.result reply payload, the
// same for a repeated result. Core replies CodeNotFound instead when it no
// longer waits for the task, and the factory drops the result.
type FactoryCommandResultReply struct {
	TaskID   string `json:"task_id"`
	Recorded bool   `json:"recorded"`
}

// FactoryCommandCancelRequest is the factory.command.cancel payload. The task
// ended cancelled when core sent it: the factory stops the command and sends
// no result.
type FactoryCommandCancelRequest struct {
	TaskID string `json:"task_id"`
}

// FactoryCommandCancelReply is the factory.command.cancel reply payload.
// Cancelled is true also for a task the instance does not know, which it
// remembers: a factory.command for it that arrives later is accepted and
// never run.
type FactoryCommandCancelReply struct {
	TaskID    string `json:"task_id"`
	Cancelled bool   `json:"cancelled"`
}

// Validate checks a call's fields: the task's id and command, the session and
// the build, and that they belong together, the files and credentials it
// gives, and the upload link. What only the factory's schema says (the
// command, its args, files and credentials) is ValidateFor's.
func (r FactoryCommandRequest) Validate() error {
	switch {
	case !syncIDPattern.MatchString(r.TaskID):
		return fmt.Errorf("task_id must be a lowercase UUID")
	case !commandIDPattern.MatchString(r.Command):
		return fmt.Errorf("command must match %s", commandIDPattern)
	case !IsLink(r.UploadURL):
		return fmt.Errorf("upload_url must be a link")
	}
	if err := r.Session.Validate(); err != nil {
		return fmt.Errorf("session: %w", err)
	}
	if err := r.Build.Validate(); err != nil {
		return fmt.Errorf("build: %w", err)
	}
	if r.Session.BuildID != r.Build.BuildID || r.Session.Target != r.Build.Target || r.Session.Platform != r.Build.Platform {
		return fmt.Errorf("session: its build_id, target and platform are its build's")
	}
	for id, f := range r.Files {
		if err := validateRequestFile(id, f); err != nil {
			return fmt.Errorf("files.%s: %w", id, err)
		}
	}
	if err := validateGivenCredentials(r.Credentials); err != nil {
		return fmt.Errorf("credentials: %w", err)
	}
	return nil
}

// ValidateFor checks a call against the factory's schema, after Validate: its
// command one of the schema's factory commands, its args that command's, and
// each file and credential they name given, of what its param takes. A
// factory runs it on each call it takes.
func (r FactoryCommandRequest) ValidateFor(s BuildSchema) error {
	if err := r.Validate(); err != nil {
		return err
	}
	c, ok := s.FactoryCommand(r.Command)
	if !ok {
		return fmt.Errorf("command %q is not one of the factory's factory commands", r.Command)
	}
	if problems := ValidateFieldValues(c.Params, r.Args); problems != nil {
		return fmt.Errorf("args: %s", joinProblems(problems))
	}
	for _, p := range c.Params {
		switch {
		case isCredentialField(p.Type):
			if _, err := FieldCredentials(p, r.Args[p.Key], r.Credentials); err != nil {
				return fmt.Errorf("args: %s: %w", p.Key, err)
			}
		case p.Type == FieldFile:
			id, ok := r.Args[p.Key].(string)
			if !ok || id == "" {
				continue
			}
			f, ok := r.Files[id]
			if !ok {
				return fmt.Errorf("args: %s: file %q is not in files", p.Key, id)
			}
			if err := ValidateFile(p, f); err != nil {
				return fmt.Errorf("args: %s: %w", p.Key, err)
			}
		}
	}
	return nil
}

// Validate checks a session's fields: its ids and number, its build's target
// and platform, when it opened, its hello's os, arch and addresses, and the
// ids and times of its identity, peers, delegates, connections and restarts.
func (s SessionRecord) Validate() error {
	switch {
	case !syncIDPattern.MatchString(s.SessionID):
		return fmt.Errorf("session_id must be a lowercase UUID")
	case s.Number < 1:
		return fmt.Errorf("number counts from 1")
	case !syncIDPattern.MatchString(s.OperationID):
		return fmt.Errorf("operation_id must be a lowercase UUID")
	case !targetIDPattern.MatchString(s.Target):
		return fmt.Errorf("target must match %s", targetIDPattern)
	case !platformPattern.MatchString(s.Platform):
		return fmt.Errorf("platform must be os/arch (%s)", platformPattern)
	case s.CreatedAt.IsZero():
		return fmt.Errorf("created_at is required")
	case s.Hello.OS == "" || s.Hello.Arch == "":
		return fmt.Errorf("hello: os and arch are required: every hello says them")
	case s.Conn < 0 || s.ConnCount < 0 || s.FeedbackErrors < 0 || s.RestartCount < 0:
		return fmt.Errorf("conn, conn_count, feedback_errors and restart_count count from 0")
	case s.Sleep != nil && (s.Sleep.Interval < 0 || s.Sleep.Jitter < 0 || s.Sleep.Jitter > 100):
		return fmt.Errorf("sleep: interval from 0, jitter a percent, 0 to 100")
	case s.FolderID != "" && !syncIDPattern.MatchString(s.FolderID):
		return fmt.Errorf("folder_id must be a lowercase UUID")
	case s.Crypto != nil && !cryptoSuitePattern.MatchString(s.Crypto.Suite):
		return fmt.Errorf("crypto: suite must match %s", cryptoSuitePattern)
	}
	if err := validateBuildID(s.BuildID); err != nil {
		return err
	}
	for i, a := range s.Hello.Addrs {
		if _, err := netip.ParseAddr(a); err != nil {
			return fmt.Errorf("hello: addrs[%d] is not an IP address", i)
		}
	}
	if a := s.Acting; a != nil {
		switch {
		case a.User == "" || a.Since.IsZero():
			return fmt.Errorf("acting: user and since are required")
		case a.CredentialID != "" && !syncIDPattern.MatchString(a.CredentialID),
			a.TaskID != "" && !syncIDPattern.MatchString(a.TaskID):
			return fmt.Errorf("acting: credential_id and task_id are lowercase UUIDs")
		}
	}
	for i, p := range s.Peers {
		if p.Address == "" || p.FirstSeen.IsZero() || p.LastSeen.IsZero() || p.Count < 0 {
			return fmt.Errorf("peers[%d]: an address, first_seen and last_seen, and a count from 0", i)
		}
	}
	for i, v := range s.Via {
		if !syncIDPattern.MatchString(v.SessionID) || !syncIDPattern.MatchString(v.TaskID) || v.Number < 1 {
			return fmt.Errorf("via[%d]: a session_id and task_id, lowercase UUIDs, and a number from 1", i)
		}
	}
	for i, c := range s.ConnChanges {
		if c.At.IsZero() || c.From < 0 || c.To < 1 {
			return fmt.Errorf("conn_changes[%d]: an at, from 0 (unknown) and to from 1", i)
		}
	}
	for i, c := range s.Connections {
		switch {
		case !moduleNamePattern.MatchString(c.Channel):
			return fmt.Errorf("connections[%d]: channel must be 1..64 characters without spaces", i)
		case !KnownKind(c.Kind):
			return fmt.Errorf("connections[%d]: kind %q is not a connection kind", i, c.Kind)
		case c.Name == "":
			return fmt.Errorf("connections[%d]: name is required", i)
		}
	}
	for i, r := range s.Restarts {
		if err := validateBuildID(r.BuildID); err != nil {
			return fmt.Errorf("restarts[%d]: %w", i, err)
		}
		if r.At.IsZero() {
			return fmt.Errorf("restarts[%d]: at is required", i)
		}
	}
	return nil
}

// Validate checks a build's fields: its id, target, platform and schema
// version, when it was made, its request (the factory.build payload of this
// build, a JSON object), its error codes, credentials' revisions and
// warnings, and its artifact and files with their links.
func (b BuildRecord) Validate() error {
	if err := validateBuildID(b.BuildID); err != nil {
		return err
	}
	switch {
	case !targetIDPattern.MatchString(b.Target):
		return fmt.Errorf("target must match %s", targetIDPattern)
	case !platformPattern.MatchString(b.Platform):
		return fmt.Errorf("platform must be os/arch (%s)", platformPattern)
	case b.SchemaVersion < 1:
		return fmt.Errorf("schema_version starts at 1")
	case b.CreatedAt.IsZero():
		return fmt.Errorf("created_at is required")
	case len(b.Warnings) > MaxBuildWarnings:
		return fmt.Errorf("too many warnings (%d > %d)", len(b.Warnings), MaxBuildWarnings)
	}
	var req struct {
		BuildID string `json:"build_id"`
	}
	switch {
	case !isJSONObject(b.Request) || json.Unmarshal(b.Request, &req) != nil:
		return fmt.Errorf("request must be the factory.build payload, a JSON object")
	case req.BuildID != b.BuildID:
		return fmt.Errorf("request is another build's (%q)", req.BuildID)
	}
	for i, e := range b.ErrorCodes {
		switch {
		case e.Code < 1 || e.Code > MaxErrorCode || e.ExitCode < 1 || e.ExitCode > MaxErrorCode:
			return fmt.Errorf("error_codes[%d]: code and exit_code are 1 to %d", i, MaxErrorCode)
		case e.Label == "":
			return fmt.Errorf("error_codes[%d]: label is required", i)
		}
	}
	for id, rev := range b.CredentialRevs {
		if !syncIDPattern.MatchString(id) || rev < 0 {
			return fmt.Errorf("credential_revs: a revision from 0 by credential id, a lowercase UUID")
		}
	}
	for _, w := range b.Warnings {
		if len(w) > MaxBuildMessageLength {
			return fmt.Errorf("warning longer than %d", MaxBuildMessageLength)
		}
	}
	if a := b.Artifact; a != nil {
		if err := a.validate(); err != nil {
			return fmt.Errorf("artifact: %w", err)
		}
		switch {
		case a.Deleted && a.URL != "":
			return fmt.Errorf("artifact: one deleted has no url")
		case !a.Deleted && !IsLink(a.URL):
			return fmt.Errorf("artifact: url must be a link")
		}
	}
	for id, f := range b.Files {
		if err := validateRequestFile(id, f); err != nil {
			return fmt.Errorf("files.%s: %w", id, err)
		}
	}
	return nil
}

// Validate checks the reply: the task's id, and accepted.
func (r FactoryCommandReply) Validate() error {
	switch {
	case !syncIDPattern.MatchString(r.TaskID):
		return fmt.Errorf("task_id must be a lowercase UUID")
	case !r.Accepted:
		return fmt.Errorf("accepted must be true: an instance that does not take a task replies with an error")
	}
	return nil
}

// Validate checks an output report's fields: its task, its seq, and its out
// within MaxFactoryCommandOut.
func (o FactoryCommandOutput) Validate() error {
	switch {
	case !syncIDPattern.MatchString(o.TaskID):
		return fmt.Errorf("task_id must be a lowercase UUID")
	case o.Seq < 1:
		return fmt.Errorf("seq counts from 1")
	case len(o.Out) > MaxFactoryCommandOut:
		return fmt.Errorf("out is %d bytes at most: the rest goes in the next report", MaxFactoryCommandOut)
	}
	return nil
}

// Validate checks a result's fields: its task, its state and what comes with
// it, its data (inline within MaxFactoryCommandInline, or as a file, never
// both) and its files.
func (r FactoryCommandResult) Validate() error {
	switch r.State {
	case EndDone, EndFailed:
	default:
		return fmt.Errorf("state must be %q or %q", EndDone, EndFailed)
	}
	returns := len(r.Data) > 0 || r.DataFile != "" || len(r.Files) > 0
	switch {
	case !syncIDPattern.MatchString(r.TaskID):
		return fmt.Errorf("task_id must be a lowercase UUID")
	case r.State == EndFailed && (r.OK || r.Exit != nil || returns):
		return fmt.Errorf("a failed task is not ok, has no exit and returns nothing: the factory could not run it")
	case r.State == EndFailed && r.Err == "":
		return fmt.Errorf("a failed task says why (err)")
	case r.OK && r.Err != "":
		return fmt.Errorf("an ok task has no err")
	case len(r.Data) > 0 && r.DataFile != "":
		return fmt.Errorf("data comes inline or as a file, not both")
	case len(r.Data) > MaxFactoryCommandInline:
		return fmt.Errorf("data inline is %d bytes at most: larger, as a file the factory put (data_file)", MaxFactoryCommandInline)
	case len(r.Data) > 0 && !isJSONObject(r.Data):
		return fmt.Errorf("data must be a JSON object")
	case r.DataFile != "" && !syncIDPattern.MatchString(r.DataFile):
		return fmt.Errorf("data_file is a file id, a lowercase UUID")
	case len(r.Files) > MaxFactoryCommandFiles:
		return fmt.Errorf("too many files (%d > %d)", len(r.Files), MaxFactoryCommandFiles)
	}
	for i, id := range r.Files {
		switch {
		case !syncIDPattern.MatchString(id):
			return fmt.Errorf("files[%d] is a file id, a lowercase UUID", i)
		case slices.Contains(r.Files[:i], id):
			return fmt.Errorf("files[%d]: %s is named twice", i, id)
		}
	}
	return checkComposeText("err", r.Err, false)
}

// Validate checks a cancel's task id.
func (r FactoryCommandCancelRequest) Validate() error {
	if !syncIDPattern.MatchString(r.TaskID) {
		return fmt.Errorf("task_id must be a lowercase UUID")
	}
	return nil
}

// joinProblems is problems by key, as one line, in the keys' order.
func joinProblems(problems map[string]string) string {
	parts := make([]string, 0, len(problems))
	for _, k := range slices.Sorted(maps.Keys(problems)) {
		parts = append(parts, k+": "+problems[k])
	}
	return strings.Join(parts, "; ")
}
