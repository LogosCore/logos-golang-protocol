package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

// The available_when example of the Module Management contract page
// (logos-docs, contracts/module-management), verbatim.
const docsConditionsManifest = `{
  "schema_version": "1",
  "actions": [
    {
      "name": "drain",
      "label": "Drain",
      "risk": "high",
      "available_when": [
        { "status": "draining", "op": "eq", "value": false, "message": "Already draining" }
      ]
    },
    {
      "name": "resume",
      "label": "Resume",
      "risk": "low",
      "available_when": [
        { "status": "draining", "op": "eq", "value": true, "message": "Not draining" }
      ]
    },
    {
      "name": "close_connections",
      "label": "Close WebSockets",
      "risk": "high",
      "available_when": [
        { "status": "ws_connections_open", "op": "gt", "value": 0 }
      ]
    }
  ],
  "status": [
    { "key": "draining", "type": "bool", "label": "Draining", "alert": true },
    { "key": "ws_connections_open", "type": "int", "label": "WebSocket connections" }
  ]
}`

func TestDocsConditionsExample(t *testing.T) {
	var m ManagementManifest
	if err := json.Unmarshal([]byte(docsConditionsManifest), &m); err != nil {
		t.Fatal(err)
	}
	if err := ValidateManifest(m); err != nil {
		t.Fatalf("the docs example is invalid: %v", err)
	}
	reasons := func(status map[string]any) []string {
		var out []string
		for _, a := range m.Actions {
			_, reason := ActionAvailable(m, a, status, nil)
			out = append(out, reason)
		}
		return out
	}
	for _, c := range []struct {
		status map[string]any
		want   string
	}{
		{map[string]any{"draining": false, "ws_connections_open": json.Number("3")}, "|Not draining|"},
		{map[string]any{"draining": true, "ws_connections_open": float64(0)}, "Already draining||Requires WebSocket connections above 0"},
		{nil, "||"}, // nothing reported yet: the module decides
	} {
		if got := strings.Join(reasons(c.status), "|"); got != c.want {
			t.Errorf("status %v: reasons %q, want %q", c.status, got, c.want)
		}
	}
}

// conditionsManifest has a subject of each kind a condition compares.
func conditionsManifest(conds ...ActionCondition) ManagementManifest {
	return ManagementManifest{
		SchemaVersion: ManagementSchemaV1,
		Properties: []PropertySpec{
			{FieldSpec: FieldSpec{Key: "log_level", Type: FieldEnum, Label: "Log level", Default: "info",
				Options: []EnumOption{{Value: "info"}, {Value: "debug"}}}, Apply: ApplyLive},
			{FieldSpec: FieldSpec{Key: "token", Type: FieldSecret}, Apply: ApplyLive},
			{FieldSpec: FieldSpec{Key: "tags", Type: FieldStringList}, Apply: ApplyLive},
		},
		Actions: []ActionSpec{{Name: "act", Risk: RiskLow, AvailableWhen: conds}},
		Status: []StatusSpec{
			{Key: "draining", Type: FieldBool, Label: "Draining"},
			{Key: "open", Type: FieldInt, Label: "Open"},
			{Key: "load", Type: FieldNumber, Label: "Load"},
			{Key: "uptime", Type: FieldDuration, Label: "Uptime"},
			{Key: "since", Type: FieldDatetime, Label: "Since"},
			{Key: "mode", Type: FieldEnum, Label: "Mode"},
			{Key: "peer", Type: FieldString},
		},
	}
}

func TestValidateConditions(t *testing.T) {
	valid := []ActionCondition{
		{Status: "draining", Op: OpEq, Value: false},
		{Status: "open", Op: OpGt, Value: 0},
		{Status: "load", Op: OpLte, Value: 2.5},
		{Status: "uptime", Op: OpGte, Value: "1m"},
		{Status: "since", Op: OpLt, Value: "2027-01-01T00:00:00Z"},
		{Status: "mode", Op: OpIn, Value: []any{"running", "paused"}}, // a status enum has no options
		{Property: "log_level", Op: OpIn, Value: []string{"info", "debug"}, Message: "Only at info or debug"},
		{Status: "peer", Op: OpNe, Value: ""},
	}
	if err := ValidateManifest(conditionsManifest(valid...)); err != nil {
		t.Fatalf("valid conditions refused: %v", err)
	}

	many := make([]any, MaxConditionValues+1)
	for i := range many {
		many[i] = i
	}
	nine := make([]ActionCondition, MaxActionConditions+1)
	for i := range nine {
		nine[i] = ActionCondition{Status: "draining", Op: OpEq, Value: false}
	}
	for _, c := range []struct {
		name, want string
		conds      []ActionCondition
	}{
		{"both subjects", "not both", []ActionCondition{{Status: "draining", Property: "log_level", Op: OpEq, Value: false}}},
		{"no subject", "status or property is required", []ActionCondition{{Op: OpEq, Value: 1}}},
		{"undeclared status", `status "nope" is not declared`, []ActionCondition{{Status: "nope", Op: OpEq, Value: 1}}},
		{"undeclared property", `property "nope" is not declared`, []ActionCondition{{Property: "nope", Op: OpEq, Value: 1}}},
		{"unknown op", `unknown op "like"`, []ActionCondition{{Status: "draining", Op: "like", Value: true}}},
		{"ordering a bool", "needs an ordered type", []ActionCondition{{Status: "draining", Op: OpGt, Value: true}}},
		{"ordering an enum", "needs an ordered type", []ActionCondition{{Property: "log_level", Op: OpLt, Value: "info"}}},
		{"wrong value type", "is not a bool value", []ActionCondition{{Status: "draining", Op: OpEq, Value: "yes"}}},
		{"no value", "is not a bool value", []ActionCondition{{Status: "draining", Op: OpEq}}},
		{"fraction for an int", "is not a int value", []ActionCondition{{Status: "open", Op: OpGt, Value: 0.5}}},
		{"bad duration", "is not a duration value", []ActionCondition{{Status: "uptime", Op: OpGt, Value: "soon"}}},
		{"in without a list", `op "in" needs a list`, []ActionCondition{{Status: "open", Op: OpIn, Value: 3}}},
		{"in an empty list", `op "in" needs a list`, []ActionCondition{{Status: "open", Op: OpIn, Value: []any{}}}},
		{"in too long a list", `op "in" needs a list`, []ActionCondition{{Status: "open", Op: OpIn, Value: many}}},
		{"in with a stray value", "is not a int value", []ActionCondition{{Status: "open", Op: OpIn, Value: []any{1, "two"}}}},
		{"not an option", "not one of the options", []ActionCondition{{Property: "log_level", Op: OpEq, Value: "verbose"}}},
		{"in with a stray option", "not one of the options", []ActionCondition{{Property: "log_level", Op: OpIn, Value: []any{"info", "verbose"}}}},
		{"a secret", "secret values cannot be compared", []ActionCondition{{Property: "token", Op: OpEq, Value: "x"}}},
		{"a list", "string_list values cannot be compared", []ActionCondition{{Property: "tags", Op: OpEq, Value: "x"}}},
		{"long message", "message longer than", []ActionCondition{{Status: "draining", Op: OpEq, Value: false, Message: strings.Repeat("x", MaxLabelLength+1)}}},
		{"too many", "too many conditions", nine},
	} {
		err := ValidateManifest(conditionsManifest(c.conds...))
		if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), `action "act"`) {
			t.Errorf("%s: %v, want an error containing %q", c.name, err, c.want)
		}
	}
}

func TestActionAvailable(t *testing.T) {
	status := map[string]any{
		"draining": true, "open": json.Number("5"), "load": 2.5, "uptime": "90s",
		"since": "2026-10-26T15:00:00Z", "mode": "running", "peer": "core-1",
	}
	values := map[string]any{"log_level": "debug"}
	for _, c := range []struct {
		cond   ActionCondition
		reason string // "" when available
	}{
		{ActionCondition{Status: "draining", Op: OpEq, Value: true}, ""},
		{ActionCondition{Status: "draining", Op: OpEq, Value: false}, "Requires Draining: No"},
		{ActionCondition{Status: "draining", Op: OpNe, Value: true}, "Requires Draining other than Yes"},
		{ActionCondition{Status: "open", Op: OpGt, Value: 0}, ""},
		{ActionCondition{Status: "open", Op: OpGt, Value: 5}, "Requires Open above 5"},
		{ActionCondition{Status: "open", Op: OpGte, Value: 5}, ""},
		{ActionCondition{Status: "open", Op: OpLt, Value: 5}, "Requires Open below 5"},
		{ActionCondition{Status: "open", Op: OpLte, Value: 4}, "Requires Open of at most 4"},
		{ActionCondition{Status: "open", Op: OpLte, Value: 5}, ""},
		{ActionCondition{Status: "open", Op: OpIn, Value: []int{1, 5}}, ""},
		{ActionCondition{Status: "load", Op: OpGte, Value: 2.5}, ""},
		{ActionCondition{Status: "load", Op: OpLt, Value: 2}, "Requires Load below 2"},
		{ActionCondition{Status: "uptime", Op: OpGte, Value: "1m"}, ""},
		{ActionCondition{Status: "uptime", Op: OpGte, Value: "2m"}, "Requires Uptime of at least 2m"},
		{ActionCondition{Status: "since", Op: OpLt, Value: "2027-01-01T00:00:00Z"}, ""},
		{ActionCondition{Status: "since", Op: OpGt, Value: "2026-10-26T16:30:00+02:00"}, ""}, // earlier, in another zone: times, not text
		{ActionCondition{Status: "mode", Op: OpIn, Value: []any{"running", "paused"}}, ""},
		{ActionCondition{Status: "mode", Op: OpIn, Value: []any{"stopped", "paused"}}, "Requires Mode: one of stopped, paused"},
		{ActionCondition{Status: "peer", Op: OpEq, Value: "core-2"}, "Requires peer: core-2"}, // no label: the key
		{ActionCondition{Property: "log_level", Op: OpEq, Value: "debug"}, ""},
		{ActionCondition{Property: "log_level", Op: OpEq, Value: "info", Message: "Only at info"}, "Only at info"},
	} {
		m := conditionsManifest(c.cond)
		if err := ValidateManifest(m); err != nil {
			t.Fatalf("%+v: %v", c.cond, err)
		}
		ok, reason := ActionAvailable(m, m.Actions[0], status, values)
		if ok != (c.reason == "") || reason != c.reason {
			t.Errorf("%+v: available %v, reason %q; want reason %q", c.cond, ok, reason, c.reason)
		}
	}
}

func TestActionAvailableUnknownValues(t *testing.T) {
	m := conditionsManifest(
		ActionCondition{Status: "draining", Op: OpEq, Value: false, Message: "Already draining"},
		ActionCondition{Status: "open", Op: OpGt, Value: 0, Message: "Nothing open"},
	)
	for name, status := range map[string]map[string]any{
		"not reported":  {},
		"reported null": {"draining": nil, "open": nil},
		"wrong type":    {"draining": "yes", "open": "many"},
	} {
		if ok, reason := ActionAvailable(m, m.Actions[0], status, nil); !ok {
			t.Errorf("%s: unavailable (%s); the module decides", name, reason)
		}
	}
	// The first condition that does not hold gives the reason.
	if _, reason := ActionAvailable(m, m.Actions[0], map[string]any{"draining": true, "open": 0}, nil); reason != "Already draining" {
		t.Errorf("reason %q", reason)
	}
	if _, reason := ActionAvailable(m, m.Actions[0], map[string]any{"draining": false, "open": 0}, nil); reason != "Nothing open" {
		t.Errorf("reason %q", reason)
	}
	// No conditions: always available.
	if ok, _ := ActionAvailable(m, ActionSpec{Name: "other", Risk: RiskLow}, map[string]any{"draining": true}, nil); !ok {
		t.Error("an action without conditions is unavailable")
	}
}

func TestActionConditionJSON(t *testing.T) {
	raw, err := json.Marshal(ActionSpec{Name: "drain", Risk: RiskHigh, AvailableWhen: []ActionCondition{
		{Status: "draining", Op: OpEq, Value: false, Message: "Already draining"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := `"available_when":[{"status":"draining","op":"eq","value":false,"message":"Already draining"}]`
	if !strings.Contains(string(raw), want) {
		t.Fatalf("json %s, want %s", raw, want)
	}
	raw, _ = json.Marshal(ActionSpec{Name: "check", Risk: RiskLow})
	if strings.Contains(string(raw), "available_when") {
		t.Fatalf("json %s: an action without conditions names none", raw)
	}
}
