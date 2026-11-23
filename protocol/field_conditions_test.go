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
	if _, err := validateBuildFields([]FieldSpec{{Key: "port", Type: FieldInt, Advanced: true}}, nil, nil); err == nil ||
		!strings.Contains(err.Error(), onlyParams) {
		t.Errorf("an advanced build field: %v", err)
	}

	// A factory's tunnel param by core's front; another command has none.
	tunnel := BuildCommand{ID: "tunnel", Op: 15, Action: ActionTunnel, Params: []FieldSpec{{Key: "timeout", Num: 2, Type: FieldDuration,
		Default: "10s", Advanced: true, When: when(ParamFront, FrontSOCKS, FrontHTTP, FrontForward)}}}
	if err := validateBuildCommand(tunnel, nil); err != nil {
		t.Errorf("a tunnel's param by its front: %v", err)
	}
	tunnel.Params[0].When = when(ParamFront, "wireguard")
	if err := validateBuildCommand(tunnel, nil); err == nil || !strings.Contains(err.Error(), `"wireguard" is not one of front's options`) {
		t.Errorf("a front core has not: %v", err)
	}
	shell := BuildCommand{ID: "shell", Op: 11, Params: []FieldSpec{{Key: "command", Num: 1, Type: FieldString, Required: true,
		When: when(ParamFront, FrontForward)}}}
	if err := validateBuildCommand(shell, nil); err == nil || !strings.Contains(err.Error(), `"front" is no param of the form`) {
		t.Errorf("a shell's param by a front: %v", err)
	}
}

// conditionalConnection is a channel's schema whose reverse-call kind goes
// through a proxy or not (its address and timeout only with route proxy),
// and whose bind-call kind calls with a cookie or not, its targets logging
// in or not (a user only with auth basic; auth has no default).
func conditionalConnection() ConnectionSchema {
	return ConnectionSchema{
		SchemaVersion: ConnectionSchemaV2,
		Version:       1,
		Kinds: map[string]ConnectionKind{
			KindReverseCall: {Fields: []FieldSpec{
				{Key: "base_url", Num: 1, Type: FieldURL, Required: true},
				{Key: "route", Num: 17, Type: FieldEnum, Default: "direct", Options: []EnumOption{{Value: "direct"}, {Value: "proxy"}}},
				{Key: "proxy_url", Num: 18, Type: FieldURL, Required: true, When: when("route", "proxy")},
				{Key: "proxy_timeout", Num: 19, Type: FieldDuration, Default: "10s", When: when("route", "proxy")},
			}},
			KindBindCall: {
				Fields: []FieldSpec{
					{Key: "carrier", Num: 2, Type: FieldEnum, Default: "body", Options: []EnumOption{{Value: "body"}, {Value: "cookie"}}},
					{Key: "cookie", Num: 3, Type: FieldString, When: when("carrier", "cookie")},
				},
				Target: []FieldSpec{
					{Key: "url", Num: 4, Type: FieldURL, Required: true},
					{Key: "auth", Num: 5, Type: FieldEnum, Options: []EnumOption{{Value: "none"}, {Value: "basic"}}},
					{Key: "user", Num: 6, Type: FieldString, Required: true, When: when("auth", "basic")},
				},
			},
		},
	}
}

// A connection schema's field may depend on an enum of its own list, as a
// param does: a kind's field on one of the kind's fields, a target field on
// one of its target's (docs: contracts/minion-connection.md, Fields that
// depend on another). Advanced stays a param's.
func TestConnectionFieldConditionsChecked(t *testing.T) {
	if err := ValidateConnectionSchema(conditionalConnection()); err != nil {
		t.Fatalf("valid: %v", err)
	}
	for name, c := range map[string]struct {
		mutate func(s ConnectionSchema)
		want   string
	}{
		"a target's enum": {func(s ConnectionSchema) { s.Kinds[KindBindCall].Fields[1].When = when("auth", "basic") },
			`kinds.bind-call: field "cookie": when: "auth" is no field of the form`},
		"a field's enum": {func(s ConnectionSchema) { s.Kinds[KindBindCall].Target[2].When = when("carrier", "cookie") },
			`kinds.bind-call: target field "user": when: "carrier" is no field of the form`},
		"another kind's enum": {func(s ConnectionSchema) { s.Kinds[KindBindCall].Fields[1].When = when("route", "proxy") },
			`"route" is no field of the form`},
		"itself": {func(s ConnectionSchema) { s.Kinds[KindReverseCall].Fields[2].When = when("proxy_url", "proxy") },
			"names the field itself"},
		"not an enum": {func(s ConnectionSchema) { s.Kinds[KindReverseCall].Fields[2].When = when("base_url", "x") },
			`"base_url" is a url`},
		"no option": {func(s ConnectionSchema) { s.Kinds[KindReverseCall].Fields[2].When = when("route", "socks") },
			`"socks" is not one of route's options`},
		"a chain": {func(s ConnectionSchema) {
			f := s.Kinds[KindReverseCall].Fields
			f[3].Type, f[3].Default, f[3].Options = FieldEnum, "fast", []EnumOption{{Value: "fast"}}
			f[2].When = when("proxy_timeout", "fast")
		}, `"proxy_timeout" has a condition of its own`},
		"advanced": {func(s ConnectionSchema) { s.Kinds[KindReverseCall].Fields[0].Advanced = true },
			"advanced is only for a command's or an action's params"},
	} {
		s := conditionalConnection()
		c.mutate(s)
		if err := ValidateConnectionSchema(s); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

// A connection's values as an endpoint's, a target's and a connection handed
// to a minion: one that does not apply is refused, required only where it
// applies, and left out of what goes on, its default too.
func TestConnectionFieldConditionValues(t *testing.T) {
	s := conditionalConnection()
	check := func(values map[string]any) map[string]string {
		return ValidateConnectionValues(s, KindReverseCall, values)
	}
	const edge = "https://edge.example.com"
	if p := check(map[string]any{"base_url": edge}); p != nil {
		t.Errorf("direct, by the default: %v", p)
	}
	if p := check(map[string]any{"base_url": edge, "proxy_url": "http://10.0.0.2:3128"}); p["proxy_url"] != "only when route is proxy" || len(p) != 1 {
		t.Errorf("a proxy's address without the proxy: %v", p)
	}
	if p := check(map[string]any{"base_url": edge, "route": "proxy"}); p["proxy_url"] != "value is required" || len(p) != 1 {
		t.Errorf("through a proxy, without its address: %v", p)
	}
	through := map[string]any{"base_url": edge, "route": "proxy", "proxy_url": "http://10.0.0.2:3128"}
	if p := check(through); p != nil {
		t.Errorf("through a proxy: %v", p)
	}
	if got := ResolveConnectionValues(s, KindReverseCall, map[string]any{"base_url": edge}); len(got) != 2 || got["route"] != "direct" {
		t.Errorf("resolved, direct: %v", got)
	}
	if got := ResolveConnectionValues(s, KindReverseCall, through); len(got) != 4 || got["proxy_timeout"] != "10s" {
		t.Errorf("resolved, through a proxy: %v", got)
	}

	// A target's by its own enum, which holds nothing until set: no default.
	const page = "https://h.example.com/a.php"
	if p := ValidateTargetValues(s, KindBindCall, map[string]any{"url": page}); p != nil {
		t.Errorf("a target without auth: %v", p)
	}
	if p := ValidateTargetValues(s, KindBindCall, map[string]any{"url": page, "user": "u"}); p["user"] != "only when auth is basic" {
		t.Errorf("a user without auth: %v", p)
	}
	if p := ValidateTargetValues(s, KindBindCall, map[string]any{"url": page, "auth": "basic"}); p["user"] != "value is required" {
		t.Errorf("basic auth without its user: %v", p)
	}
	if got := ResolveTargetValues(s, KindBindCall, map[string]any{"url": page, "auth": "basic", "user": "u"}); got["user"] != "u" {
		t.Errorf("resolved, basic auth: %v", got)
	}

	// A connection handed to a minion (add_connection, edit_connection):
	// numbered, what applies alone; off the proxy, its settings go as null.
	fields := s.KindFields(KindReverseCall)
	conn := func(params map[string]any) (HelloConnection, map[string]string) {
		return ConnectionArg(map[string]any{"channel": "http", "kind": KindReverseCall, "params": params}, fields, nil)
	}
	old, p := conn(through)
	if p != nil || old.Params[18] != "http://10.0.0.2:3128" || old.Params[19] != uint64(10000) {
		t.Fatalf("through a proxy: %v %v", old.Params, p)
	}
	if _, p := conn(map[string]any{"base_url": edge, "proxy_url": "http://10.0.0.2:3128"}); p["params.proxy_url"] != "only when route is proxy" {
		t.Errorf("a proxy's address without the proxy: %v", p)
	}
	direct, p := conn(map[string]any{"base_url": edge})
	if p != nil || len(direct.Params) != 2 {
		t.Fatalf("direct: %v %v", direct.Params, p)
	}
	patch := DiffConnection(old, direct)
	if len(patch.Params) != 3 || patch.Params[17] != "direct" {
		t.Errorf("patch %v", patch.Params)
	}
	for _, n := range []uint64{18, 19} {
		if v, ok := patch.Params[n]; !ok || v != nil {
			t.Errorf("param %d off the proxy: %v (%v), want null", n, v, ok)
		}
	}
}
