package protocol

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

// perBuildSchema is a schema whose minions take their codes per build: 1
// and 2 fixed, 3 to 5 drawn.
func perBuildSchema(t *testing.T) BuildSchema {
	t.Helper()
	s := exampleBuildSchema(t)
	s.ErrorCodesPerBuild = true
	s.ErrorCodes = []ErrorCode{
		{Code: 1, Label: "Could not start", Fixed: true},
		{Code: 2, Label: "Crashed", Fixed: true},
		{Code: 3, Label: "Its config does not read"},
		{Code: 4, Label: "Built without keys"},
		{Code: 5, Label: "No connection it can use"},
	}
	if err := ValidateBuildSchema(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestErrorCodesPerBuildSchema(t *testing.T) {
	base := perBuildSchema(t)
	all := func(fixed ...int) []ErrorCode {
		var codes []ErrorCode
		for n := 1; n <= MaxErrorCode; n++ {
			codes = append(codes, ErrorCode{Code: n, Label: "code", Fixed: slices.Contains(fixed, n)})
		}
		return codes
	}
	for _, c := range []struct {
		name string
		edit func(s *BuildSchema)
		want string // "" for valid
	}{
		{"per build", func(*BuildSchema) {}, ""},
		{"fixed without per build", func(s *BuildSchema) { s.ErrorCodesPerBuild = false }, "fixed is for a schema with error_codes_per_build"},
		{"nothing to draw", func(s *BuildSchema) { s.ErrorCodes = s.ErrorCodes[:2] }, "no error code to draw"},
		{"no codes", func(s *BuildSchema) { s.ErrorCodes = nil }, "no error code to draw"},
		// 1 and 2 fixed leave 253 codes to draw from 3 to 255: room for each.
		{"a full pool", func(s *BuildSchema) { s.ErrorCodes = all(1, 2) }, ""},
		// A fixed code in the pool takes its place there: with 2 drawn too,
		// 253 codes to draw from 252.
		{"a pool too small", func(s *BuildSchema) { s.ErrorCodes = all(1, 137) }, "253 codes to draw, from 252"},
		{"every code drawn", func(s *BuildSchema) { s.ErrorCodes = all() }, "255 codes to draw, from 253"},
	} {
		s := base
		s.ErrorCodes = append([]ErrorCode(nil), base.ErrorCodes...)
		c.edit(&s)
		err := ValidateBuildSchema(s)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}

// Core draws an exit code for each code that is not fixed, in the schema's
// order, from 3 to 255, none twice and none a fixed code; the request that
// carries them passes the factory's check. Two draws differ.
func TestDrawErrorCodes(t *testing.T) {
	s := perBuildSchema(t)
	s.ErrorCodes = append(s.ErrorCodes, ErrorCode{Code: 137, Label: "Killed", Fixed: true})
	var first []BuildErrorCode
	differ := false
	for range 200 {
		codes, err := DrawErrorCodes(s)
		if err != nil {
			t.Fatal(err)
		}
		if len(codes) != 3 || codes[0].Code != 3 || codes[1].Code != 4 || codes[2].Code != 5 {
			t.Fatalf("drawn %+v, want 3, 4 and 5 in order", codes)
		}
		exits := map[int]bool{}
		for _, c := range codes {
			if c.ExitCode < ErrorCodePoolMin || c.ExitCode > MaxErrorCode || c.ExitCode == 137 || exits[c.ExitCode] {
				t.Fatalf("drawn %+v: out of the pool, a fixed code or twice", codes)
			}
			exits[c.ExitCode] = true
		}
		r := exampleBuildRequest(t)
		r.ErrorCodes = codes
		if p := ValidateBuildRequest(s, r); p != nil {
			t.Fatalf("a drawn table: %v", p)
		}
		if first == nil {
			first = codes
		} else if !reflect.DeepEqual(first, codes) {
			differ = true
		}
	}
	if !differ {
		t.Error("200 draws, all the same")
	}

	// A pool drawn whole: every code from 3 to 255, each once.
	full := s
	full.ErrorCodes = nil
	for n := 1; n <= MaxErrorCode; n++ {
		full.ErrorCodes = append(full.ErrorCodes, ErrorCode{Code: n, Label: "code", Fixed: n < ErrorCodePoolMin})
	}
	codes, err := DrawErrorCodes(full)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int]bool{}
	for _, c := range codes {
		seen[c.ExitCode] = true
	}
	if len(codes) != 253 || len(seen) != 253 {
		t.Fatalf("a full pool: %d drawn, %d distinct", len(codes), len(seen))
	}

	none := exampleBuildSchema(t)
	none.ErrorCodesPerBuild = false
	if _, err := DrawErrorCodes(none); err == nil {
		t.Error("drawn for a factory that declares no error_codes_per_build")
	}
}

func TestRequestErrorCodes(t *testing.T) {
	s := perBuildSchema(t)
	good := []BuildErrorCode{{Code: 3, ExitCode: 87}, {Code: 4, ExitCode: 201}, {Code: 5, ExitCode: 14}}
	for _, c := range []struct {
		name  string
		codes []BuildErrorCode
		want  string // "" for no problem
	}{
		{"drawn", good, ""},
		{"none: the declared codes", nil, ""},
		{"a fixed code", append(good[:3:3], BuildErrorCode{Code: 2, ExitCode: 99}), "2: fixed"},
		{"undeclared", append(good[:3:3], BuildErrorCode{Code: 6, ExitCode: 99}), "6: not a code the factory declares"},
		{"one missing", good[:2], "5: none given"},
		{"twice", append(good[:3:3], BuildErrorCode{Code: 3, ExitCode: 99}), "3: given twice"},
		{"below the pool", []BuildErrorCode{{3, 2}, {4, 201}, {5, 14}}, "exit code 2: must be 3 to 255"},
		{"above the pool", []BuildErrorCode{{3, 256}, {4, 201}, {5, 14}}, "exit code 256: must be 3 to 255"},
		{"an exit code twice", []BuildErrorCode{{3, 87}, {4, 87}, {5, 14}}, "exit code 87: given twice"},
	} {
		r := exampleBuildRequest(t)
		r.ErrorCodes = c.codes
		p := ValidateBuildRequest(s, r)
		switch {
		case c.want == "" && p != nil:
			t.Errorf("%s: %v", c.name, p)
		case c.want != "" && (len(p) != 1 || !strings.Contains(p["error_codes"], c.want)):
			t.Errorf("%s: %v, want error_codes %q", c.name, p, c.want)
		}
	}

	// A fixed code in the pool is no exit code of another.
	withKilled := s
	withKilled.ErrorCodes = append(append([]ErrorCode(nil), s.ErrorCodes...), ErrorCode{Code: 137, Label: "Killed", Fixed: true})
	r := exampleBuildRequest(t)
	r.ErrorCodes = []BuildErrorCode{{3, 137}, {4, 201}, {5, 14}}
	if p := ValidateBuildRequest(withKilled, r); !strings.Contains(p["error_codes"], "exit code 137: a fixed code") {
		t.Errorf("a fixed code drawn: %v", p)
	}

	// A factory that takes none per build gets none.
	none := s
	none.ErrorCodesPerBuild = false
	r.ErrorCodes = good
	if p := ValidateBuildRequest(none, r); !strings.Contains(p["error_codes"], "no error codes per build") {
		t.Errorf("codes for a factory without error_codes_per_build: %v", p)
	}
}

func TestRequestExitCode(t *testing.T) {
	r := BuildRequest{ErrorCodes: []BuildErrorCode{{Code: 3, ExitCode: 87}}}
	if got := r.ExitCode(3); got != 87 {
		t.Errorf("drawn: %d, want 87", got)
	}
	if got := r.ExitCode(2); got != 2 {
		t.Errorf("fixed: %d, want 2", got)
	}
	if got := (BuildRequest{}).ExitCode(3); got != 3 {
		t.Errorf("none drawn: %d, want 3", got)
	}
}
