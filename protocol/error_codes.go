package protocol

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Minion error codes (docs: contracts/minion-build.md, Minion error codes):
// what a minion's exit code means when it stops on an error, as its
// factory declares them (BuildSchema.ErrorCodes), for an operator to look
// up. A factory whose minions take their codes from each build
// (BuildSchema.ErrorCodesPerBuild) gets them in the build request
// (BuildRequest.ErrorCodes), drawn by core (DrawErrorCodes) for every
// declared code but the fixed ones: two builds then exit with different
// codes for the same error.

// ErrorCodePoolMin is the lowest exit code core draws for a build; the
// highest is MaxErrorCode. Below it, 0 is success, 1 every runtime's
// generic failure and 2 Go's panic: a factory whose minions use them
// declares them Fixed.
const ErrorCodePoolMin = 3

// BuildErrorCode is one of a build's error codes (BuildRequest.ErrorCodes):
// the exit code its minion uses for a code its factory declares.
type BuildErrorCode struct {
	// Code is the declared code (ErrorCode.Code), never a fixed one.
	Code int `json:"code"`
	// ExitCode is what the build's minion exits with for it:
	// ErrorCodePoolMin to MaxErrorCode, once in the build, never a fixed
	// code.
	ExitCode int `json:"exit_code"`
}

// DrawErrorCodes draws a build's error codes for s, a schema that declares
// ErrorCodesPerBuild: for each declared code that is not Fixed, in the
// schema's order, an exit code at random from ErrorCodePoolMin to
// MaxErrorCode, none drawn twice and none a fixed code. Core draws them as
// it queues a build.
func DrawErrorCodes(s BuildSchema) ([]BuildErrorCode, error) {
	if !s.ErrorCodesPerBuild {
		return nil, errors.New("the factory's minions take no error codes per build")
	}
	fixed := make(map[int]bool)
	for _, c := range s.ErrorCodes {
		if c.Fixed {
			fixed[c.Code] = true
		}
	}
	pool := make([]int, 0, MaxErrorCode-ErrorCodePoolMin+1)
	for n := ErrorCodePoolMin; n <= MaxErrorCode; n++ {
		if !fixed[n] {
			pool = append(pool, n)
		}
	}
	var out []BuildErrorCode
	for _, c := range s.ErrorCodes {
		if c.Fixed {
			continue
		}
		if len(pool) == 0 {
			return nil, fmt.Errorf("more error codes to draw than %d to %d holds", ErrorCodePoolMin, MaxErrorCode)
		}
		i, err := rand.Int(rand.Reader, big.NewInt(int64(len(pool))))
		if err != nil {
			return nil, fmt.Errorf("draw an exit code: %w", err)
		}
		k := int(i.Int64())
		out = append(out, BuildErrorCode{Code: c.Code, ExitCode: pool[k]})
		// Each draw is uniform over what is left: the order of the rest
		// does not matter.
		pool[k] = pool[len(pool)-1]
		pool = pool[:len(pool)-1]
	}
	return out, nil
}

// ExitCode is the code the build's minion exits with for code, one its
// factory declares: the request's (ErrorCodes) when it carries one for it,
// code itself otherwise (a fixed code, or a build whose codes were not
// drawn).
func (r BuildRequest) ExitCode(code int) int {
	for _, e := range r.ErrorCodes {
		if e.Code == code {
			return e.ExitCode
		}
	}
	return code
}

// validateErrorCodes checks a schema's error codes: each 1 to MaxErrorCode,
// once, with a label; Fixed only with ErrorCodesPerBuild, which needs a code
// that is not fixed to draw, and room in the pool for every one.
func validateErrorCodes(s BuildSchema) error {
	seen := make(map[int]bool, len(s.ErrorCodes))
	drawn, taken := 0, 0 // codes drawn per build; fixed codes in the pool
	for _, c := range s.ErrorCodes {
		if c.Code < 1 || c.Code > MaxErrorCode {
			return fmt.Errorf("error code %d: must be 1 to %d (0 is success)", c.Code, MaxErrorCode)
		}
		if seen[c.Code] {
			return fmt.Errorf("error code %d: declared twice", c.Code)
		}
		seen[c.Code] = true
		if strings.TrimSpace(c.Label) == "" {
			return fmt.Errorf("error code %d: a label is required", c.Code)
		}
		if err := validateText(c.Label, c.Description); err != nil {
			return fmt.Errorf("error code %d: %w", c.Code, err)
		}
		switch {
		case c.Fixed && !s.ErrorCodesPerBuild:
			return fmt.Errorf("error code %d: fixed is for a schema with error_codes_per_build", c.Code)
		case !c.Fixed:
			drawn++
		case c.Code >= ErrorCodePoolMin:
			taken++
		}
	}
	if !s.ErrorCodesPerBuild {
		return nil
	}
	if drawn == 0 {
		return errors.New("error_codes_per_build: no error code to draw (none declared, or every one fixed)")
	}
	if pool := MaxErrorCode - ErrorCodePoolMin + 1 - taken; drawn > pool {
		return fmt.Errorf("error_codes_per_build: %d codes to draw, from %d", drawn, pool)
	}
	return nil
}

// validateRequestErrorCodes checks a request's error codes against s: none
// for a factory that declares no ErrorCodesPerBuild. For one that does,
// none at all (the minion exits with the declared codes), or one for every
// declared code that is not fixed, each exit code in the pool, once, and
// none a fixed code. It returns the problem, "" for none.
func validateRequestErrorCodes(s BuildSchema, codes []BuildErrorCode) string {
	if len(codes) == 0 {
		return ""
	}
	if !s.ErrorCodesPerBuild {
		return "the factory's minions take no error codes per build"
	}
	declared := make(map[int]ErrorCode, len(s.ErrorCodes))
	for _, c := range s.ErrorCodes {
		declared[c.Code] = c
	}
	given := make(map[int]bool, len(codes))
	exits := make(map[int]bool, len(codes))
	for _, e := range codes {
		d, ok := declared[e.Code]
		switch {
		case !ok:
			return fmt.Sprintf("%d: not a code the factory declares", e.Code)
		case d.Fixed:
			return fmt.Sprintf("%d: fixed, the same in every build", e.Code)
		case given[e.Code]:
			return fmt.Sprintf("%d: given twice", e.Code)
		case e.ExitCode < ErrorCodePoolMin || e.ExitCode > MaxErrorCode:
			return fmt.Sprintf("%d: exit code %d: must be %d to %d", e.Code, e.ExitCode, ErrorCodePoolMin, MaxErrorCode)
		case exits[e.ExitCode]:
			return fmt.Sprintf("exit code %d: given twice", e.ExitCode)
		case declared[e.ExitCode].Fixed:
			return fmt.Sprintf("exit code %d: a fixed code", e.ExitCode)
		}
		given[e.Code], exits[e.ExitCode] = true, true
	}
	for _, c := range s.ErrorCodes {
		if !c.Fixed && !given[c.Code] {
			return fmt.Sprintf("%d: none given: every code that is not fixed needs one", c.Code)
		}
	}
	return ""
}
