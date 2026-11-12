package protocol

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

const logBuildID = "3f6c1a52-9b1e-4c1d-8a7e-2b5f0c9d4e61"

func TestBuildLogChunkValidate(t *testing.T) {
	at := time.Date(2026, 11, 12, 15, 4, 5, 0, time.UTC)
	line := func(step, text string) BuildLogLine { return BuildLogLine{Step: step, At: at, Text: text} }
	ok := []BuildLogChunk{
		{BuildID: logBuildID, Seq: 1, Lines: []BuildLogLine{line("compile", "$ go build"), line("", "")}},
		{BuildID: logBuildID, Seq: 7, Dropped: 120},
		{BuildID: logBuildID, Seq: 2, Lines: []BuildLogLine{line("compile", strings.Repeat("é", MaxBuildLogLineBytes/2))}},
	}
	for _, c := range ok {
		if err := c.Validate(); err != nil {
			t.Errorf("refused %+v: %v", c.Seq, err)
		}
	}

	many := make([]BuildLogLine, MaxBuildLogChunkLines+1)
	for i := range many {
		many[i] = line("compile", "x")
	}
	big := make([]BuildLogLine, 20)
	for i := range big {
		big[i] = line("compile", strings.Repeat("x", MaxBuildLogLineBytes))
	}
	bad := map[string]BuildLogChunk{
		"build_id":          {BuildID: "nope", Seq: 1, Lines: []BuildLogLine{line("", "x")}},
		"seq must be 1":     {BuildID: logBuildID, Seq: 0, Lines: []BuildLogLine{line("", "x")}},
		"dropped must not":  {BuildID: logBuildID, Seq: 1, Dropped: -1, Lines: []BuildLogLine{line("", "x")}},
		"at least one line": {BuildID: logBuildID, Seq: 1},
		"too many":          {BuildID: logBuildID, Seq: 1, Lines: many},
		"bytes of text":     {BuildID: logBuildID, Seq: 1, Lines: big},
		"step must be":      {BuildID: logBuildID, Seq: 1, Lines: []BuildLogLine{line("Compile.x", "x")}},
		"at is required":    {BuildID: logBuildID, Seq: 1, Lines: []BuildLogLine{{Text: "x"}}},
		"text longer":       {BuildID: logBuildID, Seq: 1, Lines: []BuildLogLine{line("", strings.Repeat("x", MaxBuildLogLineBytes+1))}},
		"valid UTF-8":       {BuildID: logBuildID, Seq: 1, Lines: []BuildLogLine{line("", "\xff")}},
		"one line":          {BuildID: logBuildID, Seq: 1, Lines: []BuildLogLine{line("", "a\nb")}},
	}
	for want, c := range bad {
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want %q, got %v", want, err)
		}
	}
}

func TestBuildLogLineText(t *testing.T) {
	cases := map[string]string{
		"plain":       "plain",
		"crlf\r\n":    "crlf",
		"lf\n":        "lf",
		"bad\xffbyte": "bad�byte",
		"in\rside":    "in\rside",
	}
	for in, want := range cases {
		if got := BuildLogLineText(in); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
	long := strings.Repeat("ж", MaxBuildLogLineBytes) // 2 bytes each
	got := BuildLogLineText(long)
	if len(got) > MaxBuildLogLineBytes || !utf8.ValidString(got) || !strings.HasSuffix(got, "…") {
		t.Fatalf("cut to %d bytes, valid %v", len(got), utf8.ValidString(got))
	}
	if err := (BuildLogChunk{BuildID: logBuildID, Seq: 1, Lines: []BuildLogLine{{At: time.Now(), Text: got}}}).Validate(); err != nil {
		t.Fatalf("a cut line is refused: %v", err)
	}
}

// The wire form: snake_case keys, a line's step left out when it has none.
func TestBuildLogChunkJSON(t *testing.T) {
	c := BuildLogChunk{BuildID: logBuildID, Seq: 3, Dropped: 2, Lines: []BuildLogLine{
		{Step: "compile", At: time.Date(2026, 11, 12, 15, 4, 5, 250e6, time.UTC), Text: "ok"},
		{At: time.Date(2026, 11, 12, 15, 4, 6, 0, time.UTC), Text: ""},
	}}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"build_id":"` + logBuildID + `","seq":3,"lines":[{"step":"compile","at":"2026-11-12T15:04:05.25Z","text":"ok"},{"at":"2026-11-12T15:04:06Z","text":""}],"dropped":2}`
	if string(b) != want {
		t.Fatalf("got  %s\nwant %s", b, want)
	}
}
