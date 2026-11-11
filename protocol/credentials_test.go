package protocol

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func sshKey(id string) Credential {
	return Credential{ID: id, Name: "root key", Type: CredentialTypeKey, Username: "root", Key: "-----BEGIN OPENSSH PRIVATE KEY-----"}
}

func plaintext(id string) Credential {
	return Credential{ID: id, Name: "admin", Type: CredentialTypePlaintext, Username: "admin", Realm: "CORP", Password: "pw"}
}

// The table's sanity: one required field for each type but OTHER, and the
// fields Credential carries.
func TestCredentialTypeFields(t *testing.T) {
	known := map[string]bool{}
	for _, f := range CredentialFieldNames() {
		known[f] = true
	}
	for _, typ := range CredentialTypes() {
		rules, ok := CredentialTypeFields(typ)
		if !ok {
			t.Fatalf("%s: no fields", typ)
		}
		required := 0
		for _, r := range rules {
			if !known[r.Field] {
				t.Errorf("%s: field %q is not a Credential's", typ, r.Field)
			}
			if r.Required {
				required++
			}
		}
		if want := map[bool]int{true: 0, false: 1}[typ == CredentialTypeOther]; required != want {
			t.Errorf("%s: %d required fields, want %d", typ, required, want)
		}
	}
	if IsCredentialType("PASSWORD") || IsCredentialType("") {
		t.Error("an old or empty type is one")
	}
}

func TestCredentialValidate(t *testing.T) {
	for _, tc := range []struct {
		name string
		c    Credential
		want string // "" for valid
	}{
		{"a key", sshKey("k1"), ""},
		{"a plaintext", plaintext("p1"), ""},
		{"no id", Credential{Type: CredentialTypeKey, Key: "k"}, "an id"},
		{"an old type", Credential{ID: "x", Type: "SSH_KEY"}, `type "SSH_KEY" is not one of`},
		{"a key without one", Credential{ID: "x", Type: CredentialTypeKey, Username: "root"}, "a KEY needs a key"},
		{"a field its type has not", Credential{ID: "x", Type: CredentialTypeKey, Key: "k", Password: "pw"}, "a KEY has no password"},
		{"other's keys", Credential{ID: "x", Type: CredentialTypeOther, Keys: []CredentialKey{{Name: "a", Content: "b"}}}, ""},
		{"keys on a plaintext", Credential{ID: "x", Type: CredentialTypePlaintext, Password: "p", Keys: []CredentialKey{{Content: "b"}}}, "has no keys"},
		{"odd hex", Credential{ID: "x", Type: CredentialTypeHex, Hex: "abc"}, "whole bytes"},
		{"hex", Credential{ID: "x", Type: CredentialTypeHex, Hex: "DEADbeef"}, ""},
		{"an expiry", Credential{ID: "x", Type: CredentialTypeTicket, Ticket: "doIF", ExpiresAt: "2026-11-05T16:00:00Z"}, ""},
		{"a bad expiry", Credential{ID: "x", Type: CredentialTypeTicket, Ticket: "doIF", ExpiresAt: "tomorrow"}, "RFC 3339"},
	} {
		err := tc.c.Validate()
		if tc.want == "" {
			if err != nil {
				t.Errorf("%s: %v", tc.name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want %q", tc.name, err, tc.want)
		}
	}
}

// Where a credential field may be declared: what holds its values must
// belong to an operation, as credentials do.
func TestCredentialFieldScopes(t *testing.T) {
	cred := FieldSpec{Key: "login", Type: FieldCredentialList, Accept: []string{CredentialTypeKey, CredentialTypePlaintext}, MaxItems: 4}
	if err := validateConnectionFieldSpec(cred); err != nil {
		t.Errorf("a connection or target field: %v", err)
	}
	if err := validateBuildFieldSpec(cred); err != nil {
		t.Errorf("a build field: %v", err)
	}
	// Its number is checked apart (validateCommandNumbers), as validateBuildCommand does.
	if err := checkCommandParam(FieldSpec{Key: "as", Type: FieldCredential}); err != nil {
		t.Errorf("a command param: %v", err)
	}
	if err := validateFieldSpec(cred); err == nil || !strings.Contains(err.Error(), "belong to an operation") {
		t.Errorf("a module property: %v", err)
	}
	m := ManagementManifest{SchemaVersion: ManagementSchemaV1, Status: []StatusSpec{{Key: "who", Type: FieldCredential}}}
	if err := ValidateManifest(m); err == nil {
		t.Error("a credential status value")
	}
	for name, f := range map[string]FieldSpec{
		"an unknown type":    {Key: "c", Type: FieldCredential, Accept: []string{"SSH_KEY"}},
		"a type twice":       {Key: "c", Type: FieldCredential, Accept: []string{"KEY", "KEY"}},
		"a media type":       {Key: "c", Type: FieldCredential, Accept: []string{"image/png"}},
		"a default":          {Key: "c", Type: FieldCredential, Default: "x"},
		"too many items":     {Key: "c", Type: FieldCredentialList, MaxItems: MaxCredentialListItems + 1},
		"max_items on one":   {Key: "c", Type: FieldCredential, MaxItems: 2},
		"credential accept":  {Key: "c", Type: FieldString, Accept: []string{"KEY"}},
		"max_size on one":    {Key: "c", Type: FieldCredential, MaxSize: 10},
		"file takes no type": {Key: "c", Type: FieldFile, Accept: []string{"KEY"}},
	} {
		if err := validateBuildFieldSpec(f); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
}

func TestCredentialValues(t *testing.T) {
	one := FieldSpec{Key: "c", Type: FieldCredential}
	list := FieldSpec{Key: "c", Type: FieldCredentialList, MaxItems: 2, Required: true}
	for _, tc := range []struct {
		f    FieldSpec
		v    any
		want string
	}{
		{one, "k1", ""},
		{one, "", "a credential id"},
		{one, 3, "a credential id"},
		{one, strings.Repeat("x", MaxCredentialIDLength+1), "a credential id"},
		{list, []any{"k1", "p1"}, ""},
		{list, []string{"k1"}, ""},
		{list, []any{}, "required"},
		{list, []any{"k1", "k1"}, "listed twice"},
		{list, []any{"a", "b", "c"}, "at most 2"},
		{list, "k1", "list of credential ids"},
		{FieldSpec{Key: "c", Type: FieldCredentialList}, manyIDs(MaxCredentialListItems + 1), "at most 16"},
	} {
		err := ValidateValue(tc.f, tc.v)
		if tc.want == "" {
			if err != nil {
				t.Errorf("%v: %v", tc.v, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: got %v, want %q", tc.v, err, tc.want)
		}
	}
	fields := []FieldSpec{{Key: "a", Type: FieldCredential}, {Key: "b", Type: FieldCredentialList}, {Key: "s", Type: FieldString}}
	got := CredentialIDs(fields, map[string]any{"a": "k1", "b": []any{"p1", "k1"}, "s": "k9"})
	if strings.Join(got, ",") != "k1,p1" {
		t.Errorf("credential ids: %v", got)
	}
}

// What a module reads of a field: the credentials given beside the values,
// in the value's order, each of a type the field takes.
func TestFieldCredentials(t *testing.T) {
	f := FieldSpec{Key: "login", Type: FieldCredentialList, Accept: []string{CredentialTypeKey, CredentialTypePlaintext}}
	given := map[string]Credential{"k1": sshKey("k1"), "p1": plaintext("p1"),
		"h1": {ID: "h1", Type: CredentialTypeHash, Hash: "31d6"}}
	got, err := FieldCredentials(f, []any{"p1", "k1"}, given)
	if err != nil || len(got) != 2 || got[0].ID != "p1" || got[1].ID != "k1" {
		t.Fatalf("got %v, %v", got, err)
	}
	if _, err := FieldCredentials(f, []any{"x9"}, given); err == nil || !strings.Contains(err.Error(), "not given") {
		t.Errorf("an id not given: %v", err)
	}
	if _, err := FieldCredentials(f, []any{"h1"}, given); err == nil || !strings.Contains(err.Error(), "takes KEY, PLAINTEXT") {
		t.Errorf("a type the field does not take: %v", err)
	}
	if got, err := FieldCredentials(f, nil, given); err != nil || len(got) != 0 {
		t.Errorf("no value: %v %v", got, err)
	}
}

func TestValidateBuildRequest_Credentials(t *testing.T) {
	s, r := exampleBuildSchema(t), exampleBuildRequest(t)
	s.Targets[0].Fields = append(s.Targets[0].Fields, FieldSpec{Key: "signing", Num: 6, Type: FieldCredential, Accept: []string{CredentialTypeCertificate}})
	s.Channels[0].Kinds[0].Fields = append(s.Channels[0].Kinds[0].Fields, FieldSpec{Key: "proxy_login", Num: 3, Type: FieldCredentialList})
	if err := ValidateBuildSchema(s); err != nil {
		t.Fatal(err)
	}
	cert := Credential{ID: "c1", Type: CredentialTypeCertificate, Certificate: "MII…", Password: "pfx"}
	r.Values["signing"] = "c1"
	r.Connections[0].Values["proxy_login"] = []any{"p1"}
	r.Credentials = map[string]Credential{"c1": cert, "p1": plaintext("p1")}
	if p := ValidateBuildRequest(s, r); p != nil {
		t.Fatalf("credentials: %v", p)
	}
	// It survives JSON, as the factory gets it.
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var back BuildRequest
	if err := json.Unmarshal(b, &back); err != nil || ValidateBuildRequest(s, back) != nil || back.Credentials["c1"].Password != "pfx" {
		t.Fatalf("round trip: %v %v", err, ValidateBuildRequest(s, back))
	}

	delete(r.Credentials, "p1")
	if p := ValidateBuildRequest(s, r); !strings.Contains(p["connections[0].values.proxy_login"], "not given") {
		t.Errorf("a credential not given: %v", p)
	}
	r.Credentials["p1"] = plaintext("p1")
	r.Credentials["c1"] = sshKey("c1")
	if p := ValidateBuildRequest(s, r); !strings.Contains(p["values.signing"], "takes CERTIFICATE") {
		t.Errorf("a type the field does not take: %v", p)
	}
	r.Credentials["c1"] = Credential{ID: "other", Type: CredentialTypeCertificate, Certificate: "x"}
	if p := ValidateBuildRequest(s, r); p["credentials"] == "" {
		t.Errorf("a credential under another id: %v", p)
	}
}

func TestLinkFrameCredentials(t *testing.T) {
	id := bytes.Repeat([]byte{7}, 16)
	creds := map[string]Credential{"k1": sshKey("k1"), "p1": plaintext("p1")}
	call := LinkFrame{Type: LinkCall, Request: 5, Values: map[string]any{"host": "h", "credentials": []any{"k1", "p1"}},
		ID: id, Data: []byte{1}, Keys: testKeys, Credentials: creds}
	b, err := EncodeLinkFrame(call)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeLinkFrame(b)
	if err != nil || len(got.Credentials) != 2 || got.Credentials["k1"].Key != creds["k1"].Key || got.Credentials["p1"].Realm != "CORP" {
		t.Fatalf("call: %+v %v", got.Credentials, err)
	}
	f := FieldSpec{Key: "credentials", Type: FieldCredentialList}
	if list, err := FieldCredentials(f, got.Values["credentials"], got.Credentials); err != nil || len(list) != 2 {
		t.Fatalf("read back: %v %v", list, err)
	}
	open := LinkFrame{Type: LinkOpen, Request: 6, Values: map[string]any{"host": "h"}, Under: id, Keys: testKeys, Credentials: creds}
	if _, err := EncodeLinkFrame(open); err != nil {
		t.Fatalf("open: %v", err)
	}
	answer := LinkFrame{Type: LinkAnswer, Request: 5, Failure: &LinkFailure{Kind: LinkFailLogin, Msg: "refused"},
		Logins: []LinkLogin{{Credential: "k1"}, {Credential: "p1"}}}
	b, err = EncodeLinkFrame(answer)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecodeLinkFrame(b); err != nil || len(got.Logins) != 2 || got.Logins[1].Credential != "p1" || got.Logins[0].Accepted {
		t.Fatalf("answer: %+v %v", got.Logins, err)
	}

	for name, f := range map[string]LinkFrame{
		"logins on a call":       {Type: LinkCall, Request: 1, ID: id, Data: []byte{1}, Logins: []LinkLogin{{Credential: "k1"}}},
		"logins on an open":      {Type: LinkOpen, Request: 1, Logins: []LinkLogin{{Credential: "k1"}}},
		"credentials on answers": {Type: LinkAnswer, Request: 1, Status: 404, Credentials: creds},
		"a login naming none":    {Type: LinkAnswer, Request: 1, Status: 200, Logins: []LinkLogin{{}}},
		"too many logins":        {Type: LinkAnswer, Request: 1, Status: 200, Logins: make([]LinkLogin, MaxLinkLogins+1)},
		"an invalid credential": {Type: LinkCall, Request: 1, ID: id, Data: []byte{1},
			Credentials: map[string]Credential{"x": {ID: "x", Type: CredentialTypeKey}}},
		"under another id": {Type: LinkOpen, Request: 1, Credentials: map[string]Credential{"x": sshKey("k1")}},
	} {
		if _, err := EncodeLinkFrame(f); err == nil {
			t.Errorf("%s: encoded", name)
		}
	}
}

// A task's credential args: core puts the credentials in place of the ids,
// and they survive the task's CBOR to the minion.
func TestTaskCredentialArgs(t *testing.T) {
	params := []FieldSpec{
		{Key: "as", Num: 1, Type: FieldCredential, Accept: []string{CredentialTypePlaintext}},
		{Key: "keys", Num: 2, Type: FieldCredentialList},
		{Key: "path", Num: 3, Type: FieldString},
	}
	args, problems := TaskArgs(params, map[string]any{"as": "p1", "keys": []any{"k1", "k2"}, "path": "/tmp"})
	if problems != nil {
		t.Fatal(problems)
	}
	if ids, ok := args["keys"].([]string); !ok || len(ids) != 2 {
		t.Fatalf("the list's ids: %#v", args["keys"])
	}
	// Core's part.
	args["as"] = plaintext("p1")
	args["keys"] = []Credential{sshKey("k1"), sshKey("k2")}
	task := TaskItem{T: ItemTask, Task: bytes.Repeat([]byte{1}, 16), Cmd: 4, Args: WireArgs(params, args)}
	b, err := MarshalCBOR(task)
	if err != nil {
		t.Fatal(err)
	}
	var got TaskItem
	if err := UnmarshalCBOR(b, &got); err != nil {
		t.Fatal(err)
	}
	as, err := ArgCredential(got.Args, uint64(1))
	if err != nil || as.Password != "pw" || as.Realm != "CORP" {
		t.Fatalf("credential arg: %+v %v", as, err)
	}
	keys, err := ArgCredentials(got.Args, uint64(2))
	if err != nil || len(keys) != 2 || keys[1].ID != "k2" {
		t.Fatalf("credential list arg: %+v %v", keys, err)
	}
	if p, ok := ArgString(got.Args, uint64(3)); !ok || p != "/tmp" {
		t.Fatalf("a text arg beside them: %q", p)
	}
	if c, err := ArgCredential(got.Args, uint64(9)); c != nil || err != nil {
		t.Fatalf("an arg not there: %v %v", c, err)
	}
}

func manyIDs(n int) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = strings.Repeat("i", i+1)
	}
	return out
}
