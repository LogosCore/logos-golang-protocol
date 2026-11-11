package protocol

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"
)

// configSchema is a factory whose minions read a minion config: numbered
// channels, connection parameters and fields, with a file and a field it
// keeps to itself.
func configSchema() BuildSchema {
	return BuildSchema{
		SchemaVersion: BuildSchemaV3, Version: 1, MinionConfig: true, MaxTasks: true, PersistedSessions: true,
		Failover: true, Compression: []string{CompressionDeflate}, Crypto: CryptoAES256CBCHMACSHA256,
		Channels: []BuildChannel{
			{ModuleName: "http", Num: 1, Versions: []int{1}, Kinds: []BuildKind{
				{Kind: KindReverseCall, Fields: []FieldSpec{
					{Key: "method", Num: 1, Type: FieldEnum, Default: "POST", Options: []EnumOption{{Value: "GET"}, {Value: "POST"}}},
					{Key: "path_prefix", Num: 2, Type: FieldString, Default: "/"},
				}},
				{Kind: KindReversePersistent, Fields: []FieldSpec{{Key: "path_prefix", Num: 2, Type: FieldString, Default: "/"}}},
			}},
			{ModuleName: "tcp", Num: 2, Versions: []int{1}, Kinds: []BuildKind{
				{Kind: KindBindPersistent, Fields: []FieldSpec{{Key: "listen_port", Num: 1, Type: FieldInt}}},
			}},
		},
		Fields: []FieldSpec{
			{Key: "greeting", Num: 1, Type: FieldString, Default: "hello"},
			{Key: "kill_date", Num: 2, Type: FieldDatetime},
			{Key: "punches", Num: 3, Type: FieldEnumList, Options: []EnumOption{{Value: "jab"}, {Value: "hook"}}},
			{Key: "login", Num: 4, Type: FieldCredential, Accept: []string{CredentialTypePlaintext}},
			{Key: "badge", Num: 5, Type: FieldFile}, // a file's bytes are the factory's: never in a config
			{Key: "note", Num: 6, Type: FieldString},
		},
		Targets: []BuildTarget{{ID: "linux-elf", Format: "elf", Platforms: []string{"linux/amd64"}}},
		Commands: []BuildCommand{
			{ID: "sleep", Op: 1, Required: true},
			{ID: "exit", Op: 2, Required: true},
			{ID: "ls", Op: 4},
		},
	}
}

// configChannels are the channels' schemas, every kind's fields numbered.
func configChannels(module string, version int) (ConnectionSchema, bool) {
	base := []FieldSpec{
		{Key: "base_url", Num: 1, Type: FieldURL, Required: true},
		{Key: "checkin_interval", Num: 2, Type: FieldDuration, Default: "1s"},
		{Key: "checkin_jitter", Num: 3, Type: FieldInt, Default: 20},
		{Key: "tls_verify", Num: 4, Type: FieldBool, Default: false},
		{Key: "headers", Num: 5, Type: FieldStringMap},
		{Key: "proxy_login", Num: 6, Type: FieldCredential},
	}
	switch {
	case module == "http" && version == 1:
		return ConnectionSchema{SchemaVersion: ConnectionSchemaV2, Version: 1, Kinds: map[string]ConnectionKind{
			KindReverseCall:       {Fields: base},
			KindReversePersistent: {Fields: append(slices.Clone(base), FieldSpec{Key: "ws_reconnect_backoff", Num: 7, Type: FieldDuration})},
		}}, true
	case module == "tcp" && version == 1:
		return ConnectionSchema{SchemaVersion: ConnectionSchemaV2, Version: 1, Kinds: map[string]ConnectionKind{
			KindBindPersistent: {Fields: []FieldSpec{{Key: "listen_address", Num: 1, Type: FieldString}}},
		}}, true
	}
	return ConnectionSchema{}, false
}

func ptr[T any](v T) *T { return &v }

// configRequest is a whole build request of configSchema, but its config.
func configRequest(t *testing.T) BuildRequest {
	t.Helper()
	material, err := json.Marshal(AES256CBCHMACSHA256Material{EncKey: bytes.Repeat([]byte{1}, 32), MACKey: bytes.Repeat([]byte{2}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	failover := DefaultBuildFailover()
	return BuildRequest{
		BuildID: "b52d5793-58a6-497b-8b76-6c83d39d121a", Target: "linux-elf", Platform: "linux/amd64", SchemaVersion: 1,
		Values: map[string]any{
			"greeting": "hi there", "kill_date": "2026-12-01T00:00:00Z", "punches": []any{"jab", "hook"},
			"login": "c-1", "badge": "f-1", "note": "for the factory",
		},
		Commands: []string{"sleep", "exit", "ls"},
		Connections: []BuildConnection{
			{
				Endpoint: ChannelEndpointExport{
					Format: ChannelEndpointExportV2, Name: "edge", Channel: ExportChannel{ModuleName: "http", SchemaVersion: 1},
					Kind: KindReverseCall,
					Params: map[string]any{
						"base_url": "https://edge.example.com", "checkin_interval": "1s", "checkin_jitter": float64(20),
						"tls_verify": true, "headers": map[string]any{"X-Edge": "on"}, "proxy_login": "c-2",
					},
				},
				Values:     map[string]any{"method": "GET", "path_prefix": "/cdn/"},
				MaxMessage: 4096,
			},
			{
				Endpoint: ChannelEndpointExport{
					Format: ChannelEndpointExportV2, Name: "listener", Channel: ExportChannel{ModuleName: "tcp", SchemaVersion: 1},
					Kind: KindBindPersistent, Params: map[string]any{"listen_address": "0.0.0.0"},
				},
				Values:   map[string]any{"listen_port": float64(4444)},
				Failover: &ConnectionFailover{Auto: ptr(true), FailAfter: 3},
			},
		},
		Failover:    &failover,
		Crypto:      &BuildCrypto{Suite: CryptoAES256CBCHMACSHA256, Material: material},
		MaxTasks:    ptr(uint64(5)),
		Compression: CompressionDeflate,
		SessionID:   "0b9d4c3e-1f2a-4b5c-8d6e-7f8091a2b3c4",
		Credentials: map[string]Credential{
			"c-1": {ID: "c-1", Type: CredentialTypePlaintext, Username: "operator", Password: "s3cret"},
			"c-2": {ID: "c-2", Type: CredentialTypePlaintext, Username: "proxy", Password: "pw"},
		},
		Files: map[string]BuildFile{"f-1": {ID: "f-1", Name: "badge.png", Size: 10, SHA256: strings.Repeat("ab", 32),
			URL: "/api/factory/builds/b52d5793-58a6-497b-8b76-6c83d39d121a/files/f-1?expires=1&sig=x"}},
		Artifact: ArtifactUpload{UploadURL: "/api/factory/builds/b52d5793-58a6-497b-8b76-6c83d39d121a/artifact?expires=1&sig=x", MaxSize: 1 << 20},
		Deadline: time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC),
	}
}

func TestMinionConfig(t *testing.T) {
	s, r := configSchema(), configRequest(t)
	if err := ValidateBuildSchema(s); err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeMinionConfig(s, r, configChannels)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ReadMinionConfig(raw)
	if err != nil {
		t.Fatal(err)
	}

	if want, _ := uuidBytes(r.BuildID); !bytes.Equal(c.Build, want) {
		t.Errorf("build %x", c.Build)
	}
	if c.Crypto == nil || c.Crypto.Suite != CryptoAES256CBCHMACSHA256 || !bytes.Equal(c.Crypto.Keys().EncKey, bytes.Repeat([]byte{1}, 32)) ||
		!bytes.Equal(c.Crypto.Keys().MACKey, bytes.Repeat([]byte{2}, 32)) {
		t.Errorf("crypto %+v", c.Crypto)
	}
	if c.Envelope != "" || !slices.Equal(c.Ops, []uint64{1, 2, 4}) || c.MaxTasks == nil || *c.MaxTasks != 5 ||
		c.Compression != PackDeflate || len(c.Session) != 16 {
		t.Errorf("envelope %q, ops %v, max tasks %v, compression %d, session %x", c.Envelope, c.Ops, c.MaxTasks, c.Compression, c.Session)
	}
	if f := c.Failover; f == nil || !f.Enabled || f.FailAfter != 5 || !f.Wrap {
		t.Errorf("failover %+v", f)
	} else if failFor, pause, back := f.Durations(); failFor != 0 || pause != 5*time.Minute || back != time.Hour {
		t.Errorf("failover durations %s %s %s", failFor, pause, back)
	}

	// The build's fields, in their types' forms; a file stays the factory's.
	if len(c.Values) != 5 {
		t.Errorf("values %v", c.Values)
	}
	if v, _ := ArgString(c.Values, 6); v != "for the factory" {
		t.Errorf("note %q", v)
	}
	if v, _ := ArgString(c.Values, 1); v != "hi there" {
		t.Errorf("greeting %q", v)
	}
	if v, _ := ArgInt(c.Values, 2); v != time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC).Unix() {
		t.Errorf("kill date %d", v)
	}
	if v, _ := ArgStrings(c.Values, 3); !slices.Equal(v, []string{"jab", "hook"}) {
		t.Errorf("punches %v", v)
	}
	if cr, err := ArgCredential(c.Values, 4); err != nil || cr.Username != "operator" || cr.Password != "s3cret" {
		t.Errorf("login %+v %v", cr, err)
	}

	if len(c.Connections) != 2 {
		t.Fatalf("connections %+v", c.Connections)
	}
	h := c.Connections[0]
	if h.Channel != 1 || h.Version != 1 || h.Kind != KindNumReverseCall || h.MessageLimit() != 4096 || !h.FailoverAuto() {
		t.Errorf("http %+v", h)
	}
	if v, _ := ArgString(h.Params, 1); v != "https://edge.example.com" {
		t.Errorf("base url %q", v)
	}
	if v, _ := ArgDuration(h.Params, 2); v != time.Second {
		t.Errorf("check-in interval %s", v)
	}
	if v, _ := ArgInt(h.Params, 3); v != 20 {
		t.Errorf("jitter %d", v)
	}
	if v, ok := ArgBool(h.Params, 4); !v || !ok {
		t.Error("tls verify")
	}
	if v, _ := ArgStringMap(h.Params, 5); v["X-Edge"] != "on" {
		t.Errorf("headers %v", v)
	}
	if cr, err := ArgCredential(h.Params, 6); err != nil || cr.Username != "proxy" {
		t.Errorf("proxy login %+v %v", cr, err)
	}
	if m, _ := ArgString(h.Values, 1); m != "GET" {
		t.Errorf("method %q", m)
	}
	if p, _ := ArgString(h.Values, 2); p != "/cdn/" {
		t.Errorf("path prefix %q", p)
	}
	tc := c.Connections[1]
	if tc.Channel != 2 || tc.Kind != KindNumBindPersistent || !tc.FailoverAuto() || tc.FailAfter(*c.Failover) != 3 ||
		tc.MessageLimit() != MaxMinionMessageSize {
		t.Errorf("tcp %+v", tc)
	}
	if v, _ := ArgString(tc.Params, 1); v != "0.0.0.0" {
		t.Errorf("listen address %q", v)
	}
	if v, _ := ArgInt(tc.Values, 1); v != 4444 {
		t.Errorf("listen port %d", v)
	}

	// Numbers alone: no name of a field, a channel or the config's own
	// (the base URL's "https" is a value's).
	for _, name := range []string{"base_url", "checkin_interval", "path_prefix", "listen_port", "greeting", "kill_date",
		"login", "note", "badge", "enc_key", "tcp", "reverse-call", "build_id"} {
		if bytes.Contains(raw, []byte(name)) {
			t.Errorf("the config names %q", name)
		}
	}

	// The same bytes every time, whatever order Go's maps give.
	for range 20 {
		again, err := EncodeMinionConfig(s, r, configChannels)
		if err != nil || !bytes.Equal(again, raw) {
			t.Fatalf("encoded differently: %v", err)
		}
	}
}

func TestMinionConfigInTheRequest(t *testing.T) {
	s, r := configSchema(), configRequest(t)
	if p := ValidateBuildRequest(s, r); p["minion_config"] == "" || !strings.Contains(p["minion_config"], "required") {
		t.Errorf("no config: %v", p)
	}
	var err error
	if r.MinionConfig, err = EncodeMinionConfig(s, r, configChannels); err != nil {
		t.Fatal(err)
	}
	if p := ValidateBuildRequest(s, r); p != nil {
		t.Errorf("a whole request: %v", p)
	}
	// It goes as base64 in the request's JSON, and comes back as it went.
	j, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var back BuildRequest
	if err := json.Unmarshal(j, &back); err != nil || !bytes.Equal(back.MinionConfig, r.MinionConfig) {
		t.Errorf("through JSON: %v", err)
	}

	other := r
	other.BuildID = "0b9d4c3e-1f2a-4b5c-8d6e-7f8091a2b3c4"
	if p := ValidateBuildRequest(s, other); !strings.Contains(p["minion_config"], "another build's") {
		t.Errorf("another build's config: %v", p)
	}
	fewer := r
	fewer.Connections = r.Connections[:1]
	if p := ValidateBuildRequest(s, fewer); !strings.Contains(p["minion_config"], "2 connections, the request 1") {
		t.Errorf("a config of other connections: %v", p)
	}
	broken := r
	broken.MinionConfig = []byte{0xa1, 0x01}
	if p := ValidateBuildRequest(s, broken); p["minion_config"] == "" {
		t.Error("a config that does not read")
	}
	plain := s
	plain.MinionConfig = false
	if p := ValidateBuildRequest(plain, r); !strings.Contains(p["minion_config"], "read no minion config") {
		t.Errorf("a config for minions that read none: %v", p)
	}
}

func TestMinionConfigRefusals(t *testing.T) {
	cases := map[string]func(s *BuildSchema, r *BuildRequest, channels *ConnectionSchemaAt){
		`channel "tcp" has no number in the factory's schema`: func(s *BuildSchema, _ *BuildRequest, _ *ConnectionSchemaAt) {
			s.Channels[1].Num = 0
		},
		`channel "http" numbers no fields of its reverse-call connections`: func(_ *BuildSchema, _ *BuildRequest, channels *ConnectionSchemaAt) {
			*channels = func(module string, version int) (ConnectionSchema, bool) {
				cs, ok := configChannels(module, version)
				if module == "http" {
					k := cs.Kinds[KindReverseCall]
					k.Fields = slices.Clone(k.Fields)
					for i := range k.Fields {
						k.Fields[i].Num = 0
					}
					cs.Kinds[KindReverseCall] = k
				}
				return cs, ok
			}
		},
		`channel "http"'s connection schema version 2 is not known`: func(_ *BuildSchema, r *BuildRequest, _ *ConnectionSchemaAt) {
			r.Connections[0].Endpoint.Channel.SchemaVersion = 2
		},
		`command "shell" is not the factory's`: func(_ *BuildSchema, r *BuildRequest, _ *ConnectionSchemaAt) {
			r.Commands = append(r.Commands, "shell")
		},
		`values.login: login: credential c-1 was not given`: func(_ *BuildSchema, r *BuildRequest, _ *ConnectionSchemaAt) {
			delete(r.Credentials, "c-1")
		},
		`connections[0]: params.checkin_interval: `: func(_ *BuildSchema, r *BuildRequest, _ *ConnectionSchemaAt) {
			r.Connections[0].Endpoint.Params["checkin_interval"] = "soon"
		},
	}
	for want, mutate := range cases {
		s, r := configSchema(), configRequest(t)
		var channels ConnectionSchemaAt = configChannels
		mutate(&s, &r, &channels)
		if _, err := EncodeMinionConfig(s, r, channels); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want %q, got %v", want, err)
		}
	}
}

func TestMinionConfigFactorySuite(t *testing.T) {
	s, r := configSchema(), configRequest(t)
	material, _ := json.Marshal([]byte{7, 8, 9})
	r.Crypto = &BuildCrypto{Suite: "bob.knock", Material: material}
	r.Envelope = "bob.wire"
	c, err := NewMinionConfig(s, r, configChannels)
	if err != nil {
		t.Fatal(err)
	}
	if c.Crypto.Suite != "bob.knock" || !bytes.Equal(c.Crypto.Material, []byte{7, 8, 9}) || c.Crypto.EncKey != nil || c.Envelope != "bob.wire" {
		t.Errorf("a factory suite's config: %+v %q", c.Crypto, c.Envelope)
	}
	if _, err := c.Marshal(); err != nil {
		t.Error(err)
	}
	r.Envelope = EnvelopeCBOR // core's own: said by saying nothing
	if c, _ := NewMinionConfig(s, r, configChannels); c.Envelope != "" {
		t.Errorf("envelope %q", c.Envelope)
	}
}

func TestReadMinionConfigRefusals(t *testing.T) {
	good := func() MinionConfig {
		return MinionConfig{Build: make([]byte, 16), Connections: []MinionConnection{{Channel: 1, Version: 1, Kind: KindNumReverseCall}}}
	}
	if raw, err := good().Marshal(); err != nil {
		t.Fatal(err)
	} else if _, err := ReadMinionConfig(raw); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(c *MinionConfig){
		"build: 16 bytes":                func(c *MinionConfig) { c.Build = c.Build[:15] },
		"connections: at least one":      func(c *MinionConfig) { c.Connections = nil },
		"kind: 9 is no connection kind":  func(c *MinionConfig) { c.Connections[0].Kind = 9 },
		"channel: a channel's number":    func(c *MinionConfig) { c.Connections[0].Channel = 0 },
		"values: 0 is no field's number": func(c *MinionConfig) { c.Values = Args{0: "x"} },
		"params: 70000 is no field's number": func(c *MinionConfig) {
			c.Connections[0].Params = Args{70000: "x"}
		},
		"ops: 3 twice":                 func(c *MinionConfig) { c.Ops = []uint64{3, 3} },
		"compression: alg 2":           func(c *MinionConfig) { c.Compression = 2 },
		"session: 16 bytes":            func(c *MinionConfig) { c.Session = []byte{1} },
		"envelope: none for cbor":      func(c *MinionConfig) { c.Envelope = EnvelopeCBOR },
		"two 32-byte keys":             func(c *MinionConfig) { c.Crypto = &MinionCrypto{Suite: CryptoAES256CBCHMACSHA256} },
		"failover: 1 to 1000 failures": func(c *MinionConfig) { c.Failover = &MinionFailover{} },
		"max tasks:":                   func(c *MinionConfig) { c.MaxTasks = ptr(uint64(MaxTasksLimit + 1)) },
	}
	for want, mutate := range cases {
		c := good()
		mutate(&c)
		// Written as a careless factory might, past Marshal's own check.
		raw, err := MarshalCBOR(c)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ReadMinionConfig(raw); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want %q, got %v", want, err)
		}
	}
	if _, err := ReadMinionConfig([]byte("not cbor")); err == nil {
		t.Error("bytes that are no config")
	}
	if _, err := ReadMinionConfig(make([]byte, MaxMinionConfigSize+1)); err == nil {
		t.Error("a config past its limit")
	}
}

func TestFailoverAsTheMinionReadsIt(t *testing.T) {
	if DefaultMinionFailover() != DefaultBuildFailover().Minion() {
		t.Errorf("the minion's defaults %+v, the build's %+v", DefaultMinionFailover(), DefaultBuildFailover().Minion())
	}
	f := DefaultBuildFailover().Minion()
	if failFor, pause, back := f.Durations(); !f.Enabled || f.FailAfter != 5 || !f.Wrap || failFor != 0 ||
		pause != 5*time.Minute || back != time.Hour {
		t.Errorf("defaults %+v", f)
	}
}

func TestKindNumbers(t *testing.T) {
	for _, kind := range knownKinds {
		n := KindNumber(kind)
		if back, ok := KindOfNumber(n); n == 0 || !ok || back != kind {
			t.Errorf("%s: %d, back %q", kind, n, back)
		}
	}
	if KindNumber("sideways") != 0 {
		t.Error("no kind, no number")
	}
	if _, ok := KindOfNumber(0); ok {
		t.Error("0 is no kind")
	}
}

func TestListAndNumberArgs(t *testing.T) {
	args := Args{1: []any{"a", "b"}, 2: []any{"a", 3}, 3: 2.5, 4: uint64(7), 5: map[string]any{"k": "v"}, 6: map[string]any{"k": 1}}
	if v, ok := ArgStrings(args, 1); !ok || !slices.Equal(v, []string{"a", "b"}) {
		t.Errorf("strings %v", v)
	}
	if _, ok := ArgStrings(args, 2); ok {
		t.Error("a list with a number in it is no list of strings")
	}
	if v, ok := ArgNumber(args, 3); !ok || v != 2.5 {
		t.Errorf("number %v", v)
	}
	if v, ok := ArgNumber(args, 4); !ok || v != 7 {
		t.Errorf("an integer as a number %v", v)
	}
	if v, ok := ArgStringMap(args, 5); !ok || v["k"] != "v" {
		t.Errorf("string map %v", v)
	}
	if _, ok := ArgStringMap(args, 6); ok {
		t.Error("a map with a number in it is no string map")
	}
}
