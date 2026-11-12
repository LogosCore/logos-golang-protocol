package protocol

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// This file defines the live build log: while a factory builds, it sends its
// output to core in chunks of lines (factory.build.log), each line with the
// step of the plan it was written in and when. Core keeps the lines and shows
// them by step as the build runs.
//
// The live log is optional. A factory that does not send it keeps sending its
// output with the result (BuildResult.Log), as before; core shows that
// without steps. A factory that sends it may still put its log's end in the
// result: core keeps the live log when it got any, and the result's
// otherwise (a core that does not take the live log, or chunks that never
// arrived).
//
// Chunks go in order, one at a time: Seq starts at 1 and grows by one per
// chunk. A chunk whose call was lost is sent again with the same Seq; core
// keeps the first and answers the same. A Seq that skips one means a chunk
// never arrived; Dropped counts the lines the factory dropped itself before a
// chunk (it fell behind, or gave up on a chunk). Core replies CodeNotFound
// when it no longer waits for the build, and the factory stops it, as for
// progress. Any other refusal means core does not take the live log: the
// factory stops sending it for that build. The factory sends what is left
// before the result.

// TypeFactoryBuildLog is the live build log operation, factory → core.
const TypeFactoryBuildLog = "factory.build.log"

// Live build log limits.
const (
	MaxBuildLogChunkLines = 500
	MaxBuildLogChunkBytes = 64 << 10 // the lines' text, all together
	MaxBuildLogLineBytes  = 4 << 10  // one line's text; a longer one is cut
)

// BuildLogChunk is the factory.build.log payload: the next lines of a
// build's output.
type BuildLogChunk struct {
	BuildID string `json:"build_id"`
	// Seq is the chunk's number in the build's log: 1, 2, 3...
	Seq int64 `json:"seq"`
	// Lines are the output written since the last chunk, in order.
	Lines []BuildLogLine `json:"lines"`
	// Dropped is how many lines the factory dropped before these.
	Dropped int64 `json:"dropped,omitempty"`
}

// BuildLogLine is one line of a build's output.
type BuildLogLine struct {
	// Step is the id of the plan's step the line was written in; empty
	// when it is in none.
	Step string `json:"step,omitempty"`
	// At is when it was written.
	At time.Time `json:"at"`
	// Text is the line without its line break: valid UTF-8 of at most
	// MaxBuildLogLineBytes.
	Text string `json:"text"`
}

// BuildLogReply is the factory.build.log reply payload. Core replies
// CodeNotFound instead when it no longer waits for the build, and the
// factory stops it.
type BuildLogReply struct {
	BuildID string `json:"build_id"`
	Seq     int64  `json:"seq"`
	Ack     bool   `json:"ack"`
}

// Validate checks a chunk: the build id, a Seq from 1, 1 to
// MaxBuildLogChunkLines lines (none only to say lines were dropped) of
// MaxBuildLogChunkBytes in all, each a line of valid UTF-8 with its time and
// a step id or none.
func (c BuildLogChunk) Validate() error {
	if err := validateBuildID(c.BuildID); err != nil {
		return err
	}
	if c.Seq < 1 {
		return fmt.Errorf("seq must be 1 or more")
	}
	if c.Dropped < 0 {
		return fmt.Errorf("dropped must not be negative")
	}
	if len(c.Lines) == 0 && c.Dropped == 0 {
		return fmt.Errorf("lines: a chunk has at least one line, or says how many were dropped")
	}
	if len(c.Lines) > MaxBuildLogChunkLines {
		return fmt.Errorf("lines: too many (%d > %d)", len(c.Lines), MaxBuildLogChunkLines)
	}
	total := 0
	for i, l := range c.Lines {
		if err := l.validate(); err != nil {
			return fmt.Errorf("lines[%d]: %w", i, err)
		}
		total += len(l.Text)
	}
	if total > MaxBuildLogChunkBytes {
		return fmt.Errorf("lines: %d bytes of text, more than %d", total, MaxBuildLogChunkBytes)
	}
	return nil
}

func (l BuildLogLine) validate() error {
	switch {
	case l.Step != "" && !stepIDPattern.MatchString(l.Step):
		return fmt.Errorf("step must be a step id of the plan (%s) or empty", stepIDPattern)
	case l.At.IsZero():
		return fmt.Errorf("at is required")
	case len(l.Text) > MaxBuildLogLineBytes:
		return fmt.Errorf("text longer than %d bytes", MaxBuildLogLineBytes)
	case !utf8.ValidString(l.Text):
		return fmt.Errorf("text must be valid UTF-8")
	case strings.ContainsAny(l.Text, "\n"):
		return fmt.Errorf("text must be one line")
	}
	return nil
}

// BuildLogLineText makes s a line's text: valid UTF-8, its line break and a
// carriage return before it dropped, cut to MaxBuildLogLineBytes at a
// character with "…" when longer. s must hold no other line break.
func BuildLogLineText(s string) string {
	s = strings.TrimSuffix(strings.TrimSuffix(s, "\n"), "\r")
	s = strings.ToValidUTF8(s, "�")
	if len(s) <= MaxBuildLogLineBytes {
		return s
	}
	cut := MaxBuildLogLineBytes - len("…")
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}
