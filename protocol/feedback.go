package protocol

import (
	"errors"
	"fmt"
	"regexp"
	"unicode/utf8"
)

// Feedback (docs: contracts/minion-messages/sessions, Feedback): a minion's
// warnings and errors, for its operators: what it would otherwise only log
// on the host (check-ins that failed, a connection that dropped, a task that
// crashed). Any minion may send it, in any message, on every connection
// kind; core keeps it with the session and answers nothing: a message that
// went is the feedback delivered, and one sent again adds nothing, core
// keeping one entry per id.

// FeedbackItem is one warning or error (minion → core).
type FeedbackItem struct {
	T int `cbor:"0,keyasint"`
	// ID is the minion's own, FeedbackIDSize random bytes: core keeps one
	// entry per id in a session, so a resent message adds nothing.
	ID []byte `cbor:"1,keyasint"`
	// Level is FeedbackWarning or FeedbackError; a later version may add
	// levels: a reader takes one it does not know as a warning.
	Level int `cbor:"2,keyasint"`
	// Msg says what happened, for people: MaxFeedbackMsg bytes at most.
	Msg string `cbor:"3,keyasint"`
	// Code is the factory's short tag for the kind of problem
	// ("checkin_failed"), for grouping: lowercase letters, digits, "_", "-"
	// and ".", MaxFeedbackCode bytes at most.
	Code string `cbor:"4,keyasint,omitempty"`
	// Task is the task it is about, if any.
	Task []byte `cbor:"5,keyasint,omitempty"`
	// At is when it happened at the minion, unix seconds; 0 when it does
	// not say (core takes when it came).
	At uint64 `cbor:"6,keyasint,omitempty"`
	// Count is how many times it happened, the minion folding repeats into
	// one entry; 0 or 1: once.
	Count uint64 `cbor:"7,keyasint,omitempty"`
}

// Feedback levels.
const (
	FeedbackWarning = 1
	FeedbackError   = 2
)

// Feedback limits.
const (
	FeedbackIDSize  = 8
	MaxFeedbackMsg  = 1024
	MaxFeedbackCode = 64
)

var feedbackCode = regexp.MustCompile(`^[a-z0-9_.-]*$`)

// Validate checks the item: its id, a level, a message, and the code and
// task when it has them.
func (f FeedbackItem) Validate() error {
	switch {
	case len(f.ID) != FeedbackIDSize:
		return fmt.Errorf("feedback: id is %d bytes", FeedbackIDSize)
	case f.Level < 1:
		return errors.New("feedback: level is 1 (warning), 2 (error) or a later one")
	case f.Msg == "":
		return errors.New("feedback: a message")
	case len(f.Msg) > MaxFeedbackMsg:
		return fmt.Errorf("feedback: msg is %d bytes at most", MaxFeedbackMsg)
	case !utf8.ValidString(f.Msg):
		return errors.New("feedback: msg is UTF-8")
	case len(f.Code) > MaxFeedbackCode || !feedbackCode.MatchString(f.Code):
		return fmt.Errorf("feedback: code is lowercase letters, digits, _ - and ., %d bytes at most", MaxFeedbackCode)
	case f.Task != nil && len(f.Task) != 16:
		return errors.New("feedback: task is 16 bytes")
	}
	return nil
}

// FeedbackLevelName is a level's name: "warning", "error"; a level this
// version does not know is a warning.
func FeedbackLevelName(level int) string {
	if level == FeedbackError {
		return "error"
	}
	return "warning"
}
