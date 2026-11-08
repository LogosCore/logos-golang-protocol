package protocol

import (
	"strings"
	"testing"
)

func when(key string, values ...string) *FieldCondition {
	return &FieldCondition{Key: key, Values: values}
}

// conditionalForm is a form of params by its mode, as a tunnel's are by its
// front: host only with mode forward; rows (a default of its own) and
// program (required) only with mode terminal; a timeout with any, seldom
// changed.
func conditionalForm() []FieldSpec {
	return []FieldSpec{
		{Key: "mode", Type: FieldEnum, Default: "socks", Options: []EnumOption{{Value: "socks"}, {Value: "forward"}, {Value: "terminal"}}},
		{Key: "host", Type: FieldString, When: when("mode", "forward")},
		{Key: "rows", Type: FieldInt, Default: 24, When: when("mode", "terminal")},
		{Key: "program", Type: FieldString, Required: true, When: when("mode", "terminal")},
		{Key: "timeout", Type: FieldDuration, Default: "10s", Advanced: true},
	}
}

// A param applies only while its condition holds, by the value given or the
// default: otherwise it takes no default, and a value given for it is
// refused; one required is so only where it applies.
func TestTaskArgsConditions(t *testing.T) {
	form := conditionalForm()
	args, problems := TaskArgs(form, map[string]any{})
	if problems != nil || len(args) != 2 || args["mode"] != "socks" || args["timeout"] != uint64(10000) {
		t.Fatalf("by the defaults: %v %v", args, problems)
	}
	args, problems = TaskArgs(form, map[string]any{"mode": "forward", "host": "10.0.0.5"})
	if problems != nil || args["host"] != "10.0.0.5" || args["rows"] != nil {
		t.Fatalf("a forward: %v %v", args, problems)
	}
	args, problems = TaskArgs(form, map[string]any{"mode": "terminal", "program": "bash"})
	if problems != nil || args["rows"] != int64(24) || args["program"] != "bash" {
		t.Fatalf("a terminal: %v %v", args, problems)
	}
	if _, problems = TaskArgs(form, map[string]any{"mode": "terminal"}); problems["program"] != "value is required" || len(problems) != 1 {
		t.Errorf("a terminal without its program: %v", problems)
	}
	_, problems = TaskArgs(form, map[string]any{"host": "10.0.0.5", "rows": 30})
	if problems["host"] != "only when mode is forward" || problems["rows"] != "only when mode is terminal" || len(problems) != 2 {
		t.Errorf("params of other modes: %v", problems)
	}
	// A null is no value: nothing to refuse.
	if _, problems = TaskArgs(form, map[string]any{"host": nil}); problems != nil {
		t.Errorf("a null host: %v", problems)
	}
	// A mode that is none of the options: what depends on it never applies.
	if _, problems = TaskArgs(form, map[string]any{"mode": "vpn", "host": "x"}); problems["mode"] == "" || problems["host"] == "" {
		t.Errorf("an unknown mode: %v", problems)
	}
	if got := ResolveFieldValues(form, map[string]any{"mode": "forward"}); len(got) != 2 || got["mode"] != "forward" || got["timeout"] != "10s" {
		t.Errorf("resolved %v", got)
	}
}

func TestFieldConditionString(t *testing.T) {
	for want, c := range map[string]FieldCondition{
		"front is forward":                {Key: "front", Values: []string{"forward"}},
		"front is socks or http":          {Key: "front", Values: []string{"socks", "http"}},
		"front is socks, http or forward": {Key: "front", Values: []string{"socks", "http", "forward"}},
	} {
		if got := c.String(); got != want {
			t.Errorf("%v: %q, want %q", c.Values, got, want)
		}
	}
}

// A condition names an enum of the same form, with no condition of its own,
// by its options. Only params take one, and Advanced: an action's, a
// command's (which may name a param core adds to its action).
func TestParamConditionsChecked(t *testing.T) {
	withOpen := func(params []FieldSpec) ManagementManifest {
		m := validManifest()
		m.Actions = append(m.Actions, ActionSpec{Name: "open", Risk: RiskLow, Params: params})
		return m
	}
	if err := ValidateManifest(withOpen(conditionalForm())); err != nil {
		t.Fatalf("valid: %v", err)
	}
	for name, c := range map[string]struct {
		mutate func([]FieldSpec)
		want   string
	}{
		"itself":        {func(f []FieldSpec) { f[1].When = when("host", "forward") }, "names the param itself"},
		"no such param": {func(f []FieldSpec) { f[1].When = when("front", "forward") }, `"front" is no param of the form`},
		"not an enum":   {func(f []FieldSpec) { f[1].When = when("timeout", "10s") }, `"timeout" is a duration`},
		"no values":     {func(f []FieldSpec) { f[1].When = when("mode") }, "needs 1..64 values"},
		"no option":     {func(f []FieldSpec) { f[1].When = when("mode", "http") }, `"http" is not one of mode's options`},
		"twice":         {func(f []FieldSpec) { f[1].When = when("mode", "forward", "forward") }, `names "forward" twice`},
		"a chain": {func(f []FieldSpec) {
			f[3].Type, f[3].Options = FieldEnum, []EnumOption{{Value: "bash"}}
			f[1].When = when("program", "bash")
		}, `"program" has a condition of its own`},
	} {
		form := conditionalForm()
		c.mutate(form)
		if err := ValidateManifest(withOpen(form)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}

	const onlyParams = "only for a command's or an action's params"
	prop := validManifest()
	prop.Properties[0].Advanced = true
	if err := ValidateManifest(prop); err == nil || !strings.Contains(err.Error(), onlyParams) {
		t.Errorf("an advanced property: %v", err)
	}
	prop = validManifest()
	prop.Properties[0].When = when("log_level", "info")
	if err := ValidateManifest(prop); err == nil || !strings.Contains(err.Error(), onlyParams) {
		t.Errorf("a property's condition: %v", err)
	}
	if _, err := validateBuildFields([]FieldSpec{{Key: "port", Type: FieldInt, Advanced: true}}, nil); err == nil ||
		!strings.Contains(err.Error(), onlyParams) {
		t.Errorf("an advanced build field: %v", err)
	}

	// A factory's tunnel param by core's front; another command has none.
	tunnel := BuildCommand{ID: "tunnel", Op: 15, Action: ActionTunnel, Params: []FieldSpec{{Key: "timeout", Num: 2, Type: FieldDuration,
		Default: "10s", Advanced: true, When: when(ParamFront, FrontSOCKS, FrontHTTP, FrontForward)}}}
	if err := validateBuildCommand(tunnel, nil); err != nil {
		t.Errorf("a tunnel's param by its front: %v", err)
	}
	tunnel.Params[0].When = when(ParamFront, "vpn")
	if err := validateBuildCommand(tunnel, nil); err == nil || !strings.Contains(err.Error(), `"vpn" is not one of front's options`) {
		t.Errorf("a front core has not: %v", err)
	}
	shell := BuildCommand{ID: "shell", Op: 11, Params: []FieldSpec{{Key: "command", Num: 1, Type: FieldString, Required: true,
		When: when(ParamFront, FrontForward)}}}
	if err := validateBuildCommand(shell, nil); err == nil || !strings.Contains(err.Error(), `"front" is no param of the form`) {
		t.Errorf("a shell's param by a front: %v", err)
	}
}
