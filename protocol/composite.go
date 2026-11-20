package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Composite commands (docs: contracts/task-outsourcing.md, a draft). A build
// schema's command may be composite (BuildCommand.Composite): the factory's
// own code runs its task, deciding which of the session's commands to run as
// its subtasks, before and after the command's own op on the minion, one
// decision at a time. Core runs every subtask, and the own op, as an ordinary
// task of the session: the minion cannot tell them from an operator's. It
// calls the factory on its rpc_queue (TypeFactoryCompose) as the task starts,
// at each end, when a timer runs out and when an operator stops the task, one
// call at a time; the reply is the factory's decision. A composite with no op
// of its own is its subtasks alone: its task never goes to the minion.

// TypeFactoryCompose is core's call to a factory about a composite command's
// task, on the factory's rpc_queue: a ComposeRequest, answered by a Decision.
const TypeFactoryCompose = "factory.compose" // core → factory

// HeaderFileName names the file a factory puts for a task at a call's
// UploadURL.
const HeaderFileName = "Logos-File-Name"

// Composite limits.
const (
	// MaxSubtasks bounds a task's subtasks, in all: past it a subtask ends
	// refused.
	MaxSubtasks = 1000
	// MaxSubtasksUnderWay bounds a task's subtasks queued, sent or running at
	// once: more wait in the task, and are queued as others end.
	MaxSubtasksUnderWay = 32
	// MaxComposeCalls bounds the calls about one task: past it the task ends
	// failed.
	MaxComposeCalls = 10000
	// MaxComposeCtx bounds the factory's own bytes core keeps for a task.
	MaxComposeCtx = 64 << 10
	// MaxSubtaskKey bounds a subtask's key, in bytes.
	MaxSubtaskKey = 64
	// MaxSubtaskLabel bounds a subtask's as, in characters, on one line.
	MaxSubtaskLabel = 120
	// MaxComposeText bounds a status, and a finish's message or err, in
	// bytes.
	MaxComposeText = 1000
	// MaxComposeInline bounds what crosses the broker inline: an end's data
	// (its JSON) and its output, and a finish's own. Larger goes by link.
	MaxComposeInline = 16 << 10
	// MinComposeTimer and MaxComposeTimer bound a decision's After.
	MinComposeTimer = time.Second
	MaxComposeTimer = 24 * time.Hour
	// ComposeNoAnswer is how long core waits for the factory's answer
	// before it ends the task failed, and stops what is under way.
	ComposeNoAnswer = 10 * time.Minute
	// ComposeStoppedWait is how long core waits for the answer to a
	// ComposeStopped call: without one, the task ends cancelled, cleaning
	// nothing.
	ComposeStoppedWait = time.Minute
	// ComposeReplyHold is how long a reverse-call message that brings an end,
	// and asks for tasks, waits for the decision, so that what it queues goes
	// in that reply.
	ComposeReplyHold = 2 * time.Second
)

// ComposeEvent is what brings a factory.compose call.
type ComposeEvent string

const (
	// ComposeStart: the task was queued, with its args.
	ComposeStart ComposeEvent = "start"
	// ComposeEnded: something the task runs ended (ComposeRequest.End).
	ComposeEnded ComposeEvent = "ended"
	// ComposeTimer: the timer a decision set ran out (Decision.After).
	ComposeTimer ComposeEvent = "timer"
	// ComposeStopped: an operator stopped the task, and what was under way
	// has ended (ComposeRequest.Ends). Core takes the answer's Run alone:
	// cleanup subtasks, whose ends call the factory no more.
	ComposeStopped ComposeEvent = "stopped"
)

// OwnOpState is where a composite task's own op stands.
type OwnOpState string

const (
	OwnOpNotRun OwnOpState = "not_run"
	// OwnOpOut: sent to the minion, its done part not come yet.
	OwnOpOut   OwnOpState = "out"
	OwnOpEnded OwnOpState = "ended"
)

// EndState is how something a composite task ran ended.
type EndState string

const (
	// EndDone: the minion sent its last part, and OK says how it went.
	EndDone EndState = "done"
	// EndFailed: core ended it (too large for the connection, lost by its
	// minion), and Err says why.
	EndFailed EndState = "failed"
	// EndCancelled: it was stopped.
	EndCancelled EndState = "cancelled"
	// EndRefused: it failed core's checks and never ran, and Err says which.
	EndRefused EndState = "refused"
)

// ComposeRequest is the factory.compose payload: one call about a task. Core
// makes one call about a task at a time, numbered (Seq), and keeps the
// factory's Ctx between them, so any instance may answer.
type ComposeRequest struct {
	TaskID    string `json:"task_id"`
	SessionID string `json:"session_id"`
	// BuildID is the session's build.
	BuildID string `json:"build_id"`
	// Seq is the call's number for the task, from 1. A call sent again (its
	// answer lost) has the same: core takes the first answer to a Seq alone,
	// so nothing is queued twice.
	Seq   int          `json:"seq"`
	Event ComposeEvent `json:"event"`
	// Deadline is when core stops waiting for the answer: the call's timeout
	// after it was sent. The call's links last until a minute past it.
	Deadline time.Time `json:"deadline"`
	// Command and Args are the task's command and its args by param key,
	// defaults filled in.
	Command string         `json:"command"`
	Args    map[string]any `json:"args,omitempty"`
	// Actor is who queued the task, as a build's; nil for a task core queued
	// itself (an action it runs on its own).
	Actor *Actor `json:"actor,omitempty"`
	// Platform is the build's (windows/amd64), OS the os the session's minion
	// gave in its hello.
	Platform string `json:"platform"`
	OS       string `json:"os"`
	// Commands are the session's build's commands, by id: a subtask can run
	// those of them the command uses.
	Commands []string `json:"commands"`
	// OwnOp is where the task's own op stands; "" for a command with no op of
	// its own.
	OwnOp OwnOpState `json:"own_op,omitempty"`
	// SubtasksUnderWay are the task's subtasks not ended yet (queued, sent,
	// running, or waiting in the task), SubtasksEnded those ended so far.
	SubtasksUnderWay int `json:"subtasks_under_way"`
	SubtasksEnded    int `json:"subtasks_ended"`
	// Ctx is the factory's own bytes, as its decisions left them: nil while
	// there are none. Base64 in JSON.
	Ctx []byte `json:"ctx,omitempty"`
	// UploadURL is where the factory may put a file for the task (a link): a
	// PUT of the whole, with its Content-Length and its name
	// (HeaderFileName). Core answers with the file's id, size and SHA-256;
	// the file is the task's, kept as an operator's task file is.
	UploadURL string `json:"upload_url"`
	// End is what ended, for ComposeEnded.
	End *ComposeEnd `json:"end,omitempty"`
	// Ends are, for ComposeStopped, every end the factory had not heard of,
	// in order: what the stop left behind.
	Ends []ComposeEnd `json:"ends,omitempty"`
}

// ComposeEnd is what ended: one of the task's subtasks, or its own op.
type ComposeEnd struct {
	// TaskID is the subtask's task, or the task's own for its own op. It is
	// "" for a subtask that never became a task: one refused, or stopped
	// while it waited in the task.
	TaskID string `json:"task_id,omitempty"`
	// OwnOp is true for the task's own op.
	OwnOp bool `json:"own_op,omitempty"`
	// Command and Args are what ran: its command, and the args it ran with
	// (defaults filled in). Key and As are a subtask's, as its decision gave
	// them.
	Command string         `json:"command"`
	Args    map[string]any `json:"args,omitempty"`
	Key     string         `json:"key,omitempty"`
	As      string         `json:"as,omitempty"`
	State   EndState       `json:"state"`
	// OK, Err and Exit are as its last part gave them (ResultItem).
	OK   bool   `json:"ok"`
	Err  string `json:"err,omitempty"`
	Exit *int64 `json:"exit,omitempty"`
	// Data is what it returned, as JSON, as core gives it to the web app (its
	// parts joined by its result's rule), when that is MaxComposeInline bytes
	// or less; DataURL, a link to the same JSON, in its place when larger.
	Data    json.RawMessage `json:"data,omitempty"`
	DataURL string          `json:"data_url,omitempty"`
	// Out is its output, MaxComposeInline bytes or less (base64 in JSON);
	// OutURL, a link to the raw bytes, in its place when larger.
	Out    []byte `json:"out,omitempty"`
	OutURL string `json:"out_url,omitempty"`
	// Files are the files its task got (a download's, a screenshot's), each
	// with a link to fetch it whole (BuildFile.URL). A later subtask's file
	// param may name one.
	Files []BuildFile `json:"files,omitempty"`
	// Truncated and Incomplete are as its task is marked: its output and data
	// past their budget, or parts of them lost.
	Truncated  bool `json:"truncated,omitempty"`
	Incomplete bool `json:"incomplete,omitempty"`
}

// Decision is the factory.compose reply payload: the factory's decision.
// Core applies it in this order: Cancel, Run, OwnOp, After. One with nothing
// to run, no timer and no finish waits for the next end. To a ComposeStopped
// call core takes Run alone.
type Decision struct {
	// Run are subtasks to queue, in order.
	Run []Subtask `json:"run,omitempty"`
	// OwnOp sends the task's own op. It runs once at most.
	OwnOp *OwnOpRun `json:"own_op,omitempty"`
	// Cancel stops what is under way: each ends cancelled, and its end calls
	// the factory as any end does.
	Cancel *ComposeCancel `json:"cancel,omitempty"`
	// After has core call again after this long (ComposeTimer), unless
	// something ends first: a Go duration, MinComposeTimer to
	// MaxComposeTimer (Timer). The timer stops at the next call, whatever
	// brings it: each decision sets its own, or none.
	After string `json:"after,omitempty"`
	// Finish ends the task. It stands alone, with a Status at most: it stops
	// what is under way itself.
	Finish *Finish `json:"finish,omitempty"`
	// Ctx replaces the bytes core keeps (MaxComposeCtx at most, base64 in
	// JSON): an empty one clears them, nil leaves them as they are.
	Ctx *[]byte `json:"ctx,omitempty"`
	// Status is the line shown on the task while it runs: "" clears it, nil
	// leaves it as it is.
	Status *string `json:"status,omitempty"`
}

// Subtask is one a decision has core queue.
type Subtask struct {
	// Command is one the composite uses (BuildCommand.Uses), by id. Core
	// checks it and its args as an operator's task's: a subtask that fails
	// never runs, and ends refused.
	Command string `json:"command"`
	// Args are its args by param key. A file param's names a file of the
	// task's own args, one a subtask of the task got (ComposeEnd.Files), or
	// one the factory put for the task (ComposeRequest.UploadURL). A stream
	// param takes nothing in a subtask.
	Args map[string]any `json:"args,omitempty"`
	// Key is the factory's own name for it, which its end and a cancel name
	// it by: MaxSubtaskKey bytes at most, never shown. Several may share one.
	Key string `json:"key,omitempty"`
	// As is a line naming it in its view, MaxSubtaskLabel characters at most.
	As string `json:"as,omitempty"`
}

// OwnOpRun sends the task's own op: with Args by param key, or with the
// task's own args when Args is empty. Core checks them as an operator's.
type OwnOpRun struct {
	Args map[string]any `json:"args,omitempty"`
}

// ComposeCancel stops what is under way: every subtask not ended yet whose
// key is one of Keys, and the own op while it is out (OwnOp).
type ComposeCancel struct {
	Keys  []string `json:"keys,omitempty"`
	OwnOp bool     `json:"own_op,omitempty"`
}

// Finish ends the task: core stops what is under way, and once it has ended,
// the task ends as the finish says. A command with no op of its own gives its
// result here: its own Out and Data, inline up to MaxComposeInline bytes each
// or as a file the factory put for the task (OutFile, DataFile: the data as
// JSON), or a subtask's (ResultOf).
type Finish struct {
	OK bool `json:"ok"`
	// Message is a line for the operator when OK ("nothing to archive"); Err
	// says what went wrong when not. Either takes the status line's place.
	Message string `json:"message,omitempty"`
	Err     string `json:"err,omitempty"`
	// Out (base64 in JSON) and Data, a JSON object in the command's result's
	// shape, are a command's with no op of its own.
	Out      []byte          `json:"out,omitempty"`
	OutFile  string          `json:"out_file,omitempty"`
	Data     json.RawMessage `json:"data,omitempty"`
	DataFile string          `json:"data_file,omitempty"`
	// ResultOf is the task id of a subtask whose result becomes the task's,
	// for a command with no op of its own: its data, output and files. The
	// subtask ended done, and its command has the composite's result.
	ResultOf string `json:"result_of,omitempty"`
}

// Validate checks a call's fields: its ids and numbers, its event and what
// comes with it (an end for ComposeEnded, ends for ComposeStopped alone), and
// each end. A factory runs it on each call it takes.
func (r ComposeRequest) Validate() error {
	switch {
	case !syncIDPattern.MatchString(r.TaskID):
		return fmt.Errorf("task_id must be a lowercase UUID")
	case !syncIDPattern.MatchString(r.SessionID):
		return fmt.Errorf("session_id must be a lowercase UUID")
	case r.Seq < 1 || r.Seq > MaxComposeCalls:
		return fmt.Errorf("seq must be 1 to %d", MaxComposeCalls)
	case r.Deadline.IsZero():
		return fmt.Errorf("deadline is required")
	case !commandIDPattern.MatchString(r.Command):
		return fmt.Errorf("command must match %s", commandIDPattern)
	case !platformPattern.MatchString(r.Platform):
		return fmt.Errorf("platform must be os/arch (%s)", platformPattern)
	case r.OS == "":
		return fmt.Errorf("os is required: the one the session's minion gave in its hello")
	case r.SubtasksUnderWay < 0 || r.SubtasksEnded < 0:
		return fmt.Errorf("subtasks_under_way and subtasks_ended count from 0")
	case len(r.Ctx) > MaxComposeCtx:
		return fmt.Errorf("ctx longer than %d bytes", MaxComposeCtx)
	case !IsLink(r.UploadURL):
		return fmt.Errorf("upload_url must be a link")
	}
	if err := validateBuildID(r.BuildID); err != nil {
		return err
	}
	switch r.OwnOp {
	case "", OwnOpNotRun, OwnOpOut, OwnOpEnded:
	default:
		return fmt.Errorf("own_op must be %q, %q or %q", OwnOpNotRun, OwnOpOut, OwnOpEnded)
	}
	for i, id := range r.Commands {
		switch {
		case !commandIDPattern.MatchString(id):
			return fmt.Errorf("commands[%d] must match %s", i, commandIDPattern)
		case slices.Contains(r.Commands[:i], id):
			return fmt.Errorf("commands[%d]: %q is listed twice", i, id)
		}
	}
	switch r.Event {
	case ComposeStart, ComposeTimer:
		if r.End != nil || len(r.Ends) > 0 {
			return fmt.Errorf("a %s call carries no end", r.Event)
		}
	case ComposeEnded:
		switch {
		case r.End == nil:
			return fmt.Errorf("an ended call carries its end")
		case len(r.Ends) > 0:
			return fmt.Errorf("ends come with a stopped call alone")
		}
		if err := r.validateEnd(*r.End); err != nil {
			return fmt.Errorf("end: %w", err)
		}
	case ComposeStopped:
		if r.End != nil {
			return fmt.Errorf("a stopped call carries ends, not an end")
		}
		for i, e := range r.Ends {
			if err := r.validateEnd(e); err != nil {
				return fmt.Errorf("ends[%d]: %w", i, err)
			}
		}
	default:
		return fmt.Errorf("event must be %q, %q, %q or %q", ComposeStart, ComposeEnded, ComposeTimer, ComposeStopped)
	}
	return nil
}

// validateEnd checks an end of the call's task: the end itself, and an own
// op's against the task.
func (r ComposeRequest) validateEnd(e ComposeEnd) error {
	if err := e.Validate(); err != nil {
		return err
	}
	if !e.OwnOp {
		return nil
	}
	switch {
	case r.OwnOp == "":
		return fmt.Errorf("an own op's end, for a command with no op of its own")
	case e.TaskID != r.TaskID || e.Command != r.Command:
		return fmt.Errorf("an own op's task_id and command are the task's")
	}
	return nil
}

// Validate checks an end's fields: its state and what comes with it, its key
// and label, its data and output (inline within MaxComposeInline, or by
// link, never both) and its files.
func (e ComposeEnd) Validate() error {
	switch e.State {
	case EndDone, EndFailed, EndCancelled, EndRefused:
	default:
		return fmt.Errorf("state must be %q, %q, %q or %q", EndDone, EndFailed, EndCancelled, EndRefused)
	}
	switch {
	case e.TaskID == "" && (e.OwnOp || (e.State != EndRefused && e.State != EndCancelled)):
		return fmt.Errorf("task_id is required: only a subtask refused, or stopped while it waited in the task, has none")
	case e.TaskID != "" && !syncIDPattern.MatchString(e.TaskID):
		return fmt.Errorf("task_id must be a lowercase UUID")
	case !commandIDPattern.MatchString(e.Command):
		return fmt.Errorf("command must match %s", commandIDPattern)
	case e.OwnOp && (e.Key != "" || e.As != ""):
		return fmt.Errorf("an own op has no key or as: a subtask's")
	case e.OK && e.State != EndDone:
		return fmt.Errorf("only a done end is ok")
	case e.Err == "" && (e.State == EndFailed || e.State == EndRefused):
		return fmt.Errorf("a %s end says why (err)", e.State)
	case e.Exit != nil && e.State != EndDone:
		return fmt.Errorf("an exit comes with a done end alone")
	case len(e.Data) > 0 && e.DataURL != "", len(e.Out) > 0 && e.OutURL != "":
		return fmt.Errorf("data and output come inline or by link, not both")
	case len(e.Data) > MaxComposeInline:
		return fmt.Errorf("data inline is %d bytes at most: larger, by data_url", MaxComposeInline)
	case len(e.Out) > MaxComposeInline:
		return fmt.Errorf("out inline is %d bytes at most: larger, by out_url", MaxComposeInline)
	case e.DataURL != "" && !IsLink(e.DataURL), e.OutURL != "" && !IsLink(e.OutURL):
		return fmt.Errorf("data_url and out_url must be links")
	case len(e.Data) > 0 && !isJSONObject(e.Data):
		return fmt.Errorf("data must be a JSON object")
	}
	if err := checkSubtaskName(e.Key, e.As); err != nil {
		return err
	}
	for i, f := range e.Files {
		if err := validateTaskFile(f); err != nil {
			return fmt.Errorf("files[%d]: %w", i, err)
		}
	}
	return nil
}

// Validate checks a decision by itself: a finish alone (with a status at
// most), each subtask's command, key and label, a cancel that names
// something, the timer's range, the sizes of ctx and status, and the
// finish's fields. What only its call says is ValidateFor's; what only core
// knows (a subtask's command among those the composite uses, its args, a
// result_of's subtask) core checks as it applies it.
func (d Decision) Validate() error {
	if d.Finish != nil && (len(d.Run) > 0 || d.OwnOp != nil || d.Cancel != nil || d.After != "" || d.Ctx != nil) {
		return fmt.Errorf("a finish stands alone, with a status at most: it stops what is under way itself")
	}
	if len(d.Run) > MaxSubtasks {
		return fmt.Errorf("run: %d subtasks, a task has %d at most", len(d.Run), MaxSubtasks)
	}
	for i, s := range d.Run {
		if !commandIDPattern.MatchString(s.Command) {
			return fmt.Errorf("run[%d]: command must match %s", i, commandIDPattern)
		}
		if err := checkSubtaskName(s.Key, s.As); err != nil {
			return fmt.Errorf("run[%d]: %w", i, err)
		}
	}
	if c := d.Cancel; c != nil {
		if len(c.Keys) == 0 && !c.OwnOp {
			return fmt.Errorf("cancel names nothing: keys, or own_op")
		}
		for i, k := range c.Keys {
			if k == "" {
				return fmt.Errorf("cancel: keys[%d] is empty", i)
			}
			if err := checkSubtaskName(k, ""); err != nil {
				return fmt.Errorf("cancel: keys[%d]: %w", i, err)
			}
		}
	}
	if _, err := d.Timer(); err != nil {
		return err
	}
	if d.Ctx != nil && len(*d.Ctx) > MaxComposeCtx {
		return fmt.Errorf("ctx longer than %d bytes", MaxComposeCtx)
	}
	if d.Status != nil {
		if err := checkComposeText("status", *d.Status, true); err != nil {
			return err
		}
	}
	if d.Finish != nil {
		if err := d.Finish.validate(); err != nil {
			return fmt.Errorf("finish: %w", err)
		}
	}
	return nil
}

// ValidateFor checks a decision against the call it answers, after Validate:
// an own op for a command that has one and has not sent it, and a finish's
// own result for a command with none. To a stopped call core takes Run
// alone, so the rest is not checked there.
func (d Decision) ValidateFor(r ComposeRequest) error {
	if err := d.Validate(); err != nil {
		return err
	}
	if r.Event == ComposeStopped {
		return nil
	}
	noOp := r.OwnOp == ""
	switch {
	case d.OwnOp != nil && noOp, d.Cancel != nil && d.Cancel.OwnOp && noOp:
		return fmt.Errorf("own_op: the command has no op of its own")
	case d.OwnOp != nil && r.OwnOp != OwnOpNotRun:
		return fmt.Errorf("own_op: it was sent already, and runs once")
	}
	if f := d.Finish; f != nil && !noOp && f.givesResult() {
		return fmt.Errorf("finish: the command's result is its own op's: only one with no op of its own gives out, data or result_of")
	}
	return nil
}

// Timer is the decision's After as a duration: 0 when it sets none.
func (d Decision) Timer() (time.Duration, error) {
	return durationLimit("after", d.After, MinComposeTimer, MaxComposeTimer)
}

// givesResult reports whether the finish gives a result of its own: output,
// data, or a subtask's.
func (f Finish) givesResult() bool {
	return len(f.Out) > 0 || f.OutFile != "" || len(f.Data) > 0 || f.DataFile != "" || f.ResultOf != ""
}

func (f Finish) validate() error {
	switch {
	case f.OK && f.Err != "":
		return fmt.Errorf("an ok finish says a message, not an err")
	case !f.OK && f.Err == "":
		return fmt.Errorf("a finish that is not ok says why (err)")
	case !f.OK && f.Message != "":
		return fmt.Errorf("a finish that is not ok says an err, not a message")
	case len(f.Out) > 0 && f.OutFile != "", len(f.Data) > 0 && f.DataFile != "":
		return fmt.Errorf("out and data come inline or as a file, not both")
	case len(f.Out) > MaxComposeInline:
		return fmt.Errorf("out inline is %d bytes at most: larger, as a file the factory put (out_file)", MaxComposeInline)
	case len(f.Data) > MaxComposeInline:
		return fmt.Errorf("data inline is %d bytes at most: larger, as a file the factory put (data_file)", MaxComposeInline)
	case len(f.Data) > 0 && !isJSONObject(f.Data):
		return fmt.Errorf("data must be a JSON object")
	case f.OutFile != "" && !syncIDPattern.MatchString(f.OutFile), f.DataFile != "" && !syncIDPattern.MatchString(f.DataFile):
		return fmt.Errorf("out_file and data_file are file ids, lowercase UUIDs")
	case f.ResultOf != "" && !syncIDPattern.MatchString(f.ResultOf):
		return fmt.Errorf("result_of is a subtask's task id, a lowercase UUID")
	case f.ResultOf != "" && (len(f.Out) > 0 || f.OutFile != "" || len(f.Data) > 0 || f.DataFile != ""):
		return fmt.Errorf("a finish that takes a subtask's result (result_of) gives no out or data of its own")
	}
	if err := checkComposeText("message", f.Message, false); err != nil {
		return err
	}
	return checkComposeText("err", f.Err, false)
}

// checkSubtaskName checks a subtask's key (MaxSubtaskKey bytes) and as (a
// line of MaxSubtaskLabel characters at most).
func checkSubtaskName(key, as string) error {
	switch {
	case len(key) > MaxSubtaskKey:
		return fmt.Errorf("key is %d bytes at most", MaxSubtaskKey)
	case !utf8.ValidString(key) || strings.IndexFunc(key, unicode.IsControl) >= 0:
		return fmt.Errorf("key must be text, without control characters")
	case utf8.RuneCountInString(as) > MaxSubtaskLabel:
		return fmt.Errorf("as is %d characters at most", MaxSubtaskLabel)
	case !utf8.ValidString(as) || strings.IndexFunc(as, unicode.IsControl) >= 0:
		return fmt.Errorf("as must be one line of text")
	}
	return nil
}

// checkComposeText checks a status, a message or an err: UTF-8 of
// MaxComposeText bytes at most; one line when line.
func checkComposeText(name, s string, line bool) error {
	switch {
	case len(s) > MaxComposeText:
		return fmt.Errorf("%s is %d bytes at most", name, MaxComposeText)
	case !utf8.ValidString(s):
		return fmt.Errorf("%s must be UTF-8", name)
	case line && strings.IndexFunc(s, unicode.IsControl) >= 0:
		return fmt.Errorf("%s must be one line of text", name)
	}
	return nil
}

// validateTaskFile checks a file core keeps for a task, as an end lists it:
// its id, name, size, SHA-256 and link.
func validateTaskFile(f BuildFile) error {
	switch {
	case !syncIDPattern.MatchString(f.ID):
		return fmt.Errorf("id must be a lowercase UUID")
	case f.Name == "":
		return fmt.Errorf("name is required")
	case f.Size < 0:
		return fmt.Errorf("size must not be negative")
	case !sha256Pattern.MatchString(f.SHA256):
		return fmt.Errorf("sha256 must be 64 lowercase hex digits")
	case !IsLink(f.URL):
		return fmt.Errorf("url must be a link")
	}
	return nil
}

// isJSONObject reports whether raw, valid JSON, is an object.
func isJSONObject(raw []byte) bool {
	trimmed := bytes.TrimLeft(raw, " \t\r\n")
	return len(trimmed) > 0 && trimmed[0] == '{' && json.Valid(raw)
}

// HasOp reports whether the command has an op of its own: every command but
// a composite one that is its subtasks alone.
func (c BuildCommand) HasOp() bool { return c.Op != 0 }

// PickCommands returns the commands a build of target t has when an operator
// picks ids (DefaultCommands for a build that names none): those picked and
// the target's required ones, with what each composite among them uses, and
// what those use in turn, in the schema's order. A composite with no op of
// its own builds nothing, so it is not among them: a session has it once its
// build has every command it uses (SessionCommands).
func (s BuildSchema) PickCommands(t BuildTarget, ids []string) []string {
	picked := map[string]bool{}
	var pick func(id string)
	pick = func(id string) {
		c, ok := s.Command(id)
		if !ok || !c.For(t.ID) || picked[id] {
			return
		}
		picked[id] = true
		for _, u := range c.Uses {
			pick(u)
		}
	}
	for _, id := range ids {
		pick(id)
	}
	for _, c := range s.TargetCommands(t) {
		if c.Required {
			pick(c.ID)
		}
	}
	out := []string{}
	for _, c := range s.TargetCommands(t) {
		if picked[c.ID] && c.HasOp() {
			out = append(out, c.ID)
		}
	}
	return out
}

// SessionCommands returns what a session of a build of target t can run: the
// build's commands, and each composite with no op of its own whose commands
// it uses the build all has, in the schema's order.
func (s BuildSchema) SessionCommands(t BuildTarget, build []string) []string {
	out := []string{}
	for _, c := range s.TargetCommands(t) {
		switch {
		case slices.Contains(build, c.ID):
			out = append(out, c.ID)
		case c.Composite && !c.HasOp() && len(c.Uses) > 0 &&
			!slices.ContainsFunc(c.Uses, func(u string) bool { return !slices.Contains(build, u) }):
			out = append(out, c.ID)
		}
	}
	return out
}

// validateComposite checks a command's composite fields by themselves: uses
// with composite alone, each once; no tunnel or delegate action; and, for
// one with no op of its own, no stream param (its task never goes to the
// minion). validateComposites checks the commands it uses.
func validateComposite(c BuildCommand) error {
	if !c.Composite {
		if len(c.Uses) > 0 {
			return fmt.Errorf("uses: only a composite command uses others")
		}
		return nil
	}
	if len(c.Uses) == 0 {
		return fmt.Errorf("uses: a composite command names the commands its subtasks run")
	}
	for i, u := range c.Uses {
		if slices.Contains(c.Uses[:i], u) {
			return fmt.Errorf("uses: %q is named twice", u)
		}
	}
	if IsTunnelAction(c.Action) || IsDelegateAction(c.Action) {
		return fmt.Errorf("action %q: a composite is no tunnel and no delegate", c.Action)
	}
	if !c.HasOp() {
		for _, p := range c.Params {
			if p.Type == FieldStream {
				return fmt.Errorf("param %q: a composite with no op of its own takes no stream: its task never goes to the minion", p.Key)
			}
		}
	}
	return nil
}

// validateComposites checks what each composite command of s uses: commands
// of the schema with an op of their own, each on every target the composite
// is on.
func validateComposites(s BuildSchema) error {
	for _, c := range s.Commands {
		for _, id := range c.Uses {
			u, ok := s.Command(id)
			switch {
			case !ok:
				return fmt.Errorf("command %q: uses: %q is not a command of this factory", c.ID, id)
			case !u.HasOp():
				return fmt.Errorf("command %q: uses: %q has no op of its own, and a subtask runs a command's op", c.ID, id)
			}
			for _, t := range s.Targets {
				if c.For(t.ID) && !u.For(t.ID) {
					return fmt.Errorf("command %q: uses: %q is not on target %q, which %q is on", c.ID, id, t.ID, c.ID)
				}
			}
		}
	}
	return nil
}
