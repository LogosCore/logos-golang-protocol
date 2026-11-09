package protocol

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestBuildSchemaCodecs(t *testing.T) {
	codec := func() *BuildCodec { return &BuildCodec{Growth: 250, Overhead: 200, Timeout: "2s"} }
	for _, tc := range []struct {
		want string // "" for valid
		edit func(*BuildSchema)
	}{
		{"", func(s *BuildSchema) { s.Envelope = EnvelopeJSON }},
		{"", func(s *BuildSchema) { s.Envelope = EnvelopeCBOR }},
		{"", func(s *BuildSchema) { s.Crypto, s.Codec = "acme.xchacha", codec() }},
		{"", func(s *BuildSchema) { s.Targets[2].Envelope, s.Codec = "acme.xml", codec() }},
		{"", func(s *BuildSchema) { s.Targets[2].Crypto = CryptoAES256CBCHMACSHA256 }},
		{"", func(s *BuildSchema) { s.Crypto, s.Codec = "acme.x", &BuildCodec{Growth: 100} }},
		{`crypto suite "rot13": core's are aes-256-cbc-hmac-sha256`, func(s *BuildSchema) { s.Crypto = "rot13" }},
		{`envelope "xml": core's are cbor, json`, func(s *BuildSchema) { s.Envelope = "xml" }},
		{`envelope "XML" must match`, func(s *BuildSchema) { s.Envelope = "XML" }},
		{`target "linux-elf": envelope "yaml"`, func(s *BuildSchema) { s.Targets[2].Envelope = "yaml" }},
		{`target "linux-elf": crypto suite "Acme.x" must match`, func(s *BuildSchema) { s.Targets[2].Crypto = "Acme.x" }},
		{"codec: required, the factory names its own acme.xchacha, acme.xml", func(s *BuildSchema) {
			s.Crypto, s.Targets[0].Envelope = "acme.xchacha", "acme.xml"
		}},
		{"codec: only for a factory that names", func(s *BuildSchema) { s.Envelope, s.Codec = EnvelopeJSON, codec() }},
		{"codec: growth is 100 to 400", func(s *BuildSchema) { s.Crypto, s.Codec = "acme.x", &BuildCodec{Growth: 99} }},
		{"codec: growth is 100 to 400", func(s *BuildSchema) { s.Crypto, s.Codec = "acme.x", &BuildCodec{Growth: 401} }},
		{"codec: overhead is 0 to 4096", func(s *BuildSchema) {
			s.Crypto, s.Codec = "acme.x", &BuildCodec{Growth: 100, Overhead: 4097}
		}},
		{"codec: timeout must be a duration from 100ms to 30s", func(s *BuildSchema) {
			s.Crypto, s.Codec = "acme.x", &BuildCodec{Growth: 100, Timeout: "31s"}
		}},
		{"codec: timeout must be", func(s *BuildSchema) { s.Crypto, s.Codec = "acme.x", &BuildCodec{Growth: 100, Timeout: "5"} }},
	} {
		s := exampleBuildSchema(t)
		tc.edit(&s)
		err := ValidateBuildSchema(s)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("valid schema refused: %v", err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("want %q, got %v", tc.want, err)
		}
	}
}

func TestTargetCodec(t *testing.T) {
	s := exampleBuildSchema(t)
	s.Crypto, s.Codec = "acme.xchacha", &BuildCodec{Growth: 150}
	s.Targets[1].Envelope = "acme.xml"
	s.Targets[2].Crypto, s.Targets[2].Envelope = CryptoAES256CBCHMACSHA256, EnvelopeJSON
	if err := ValidateBuildSchema(s); err != nil {
		t.Fatal(err)
	}
	for i, want := range []struct {
		codec  Codec
		layers []int
	}{
		{Codec{"acme.xchacha", EnvelopeCBOR}, []int{CodecLayerSuite}},
		{Codec{"acme.xchacha", "acme.xml"}, []int{CodecLayerSuite, CodecLayerEnvelope}},
		{Codec{CryptoAES256CBCHMACSHA256, EnvelopeJSON}, nil},
	} {
		c := s.TargetCodec(s.Targets[i])
		if c != want.codec || !slices.Equal(c.Layers(), want.layers) || c.Translated() != (want.layers != nil) {
			t.Errorf("target %d: %+v %v", i, c, c.Layers())
		}
	}
	if !s.Translates() || exampleBuildSchema(t).Translates() {
		t.Error("Translates")
	}
	if got := s.FactoryCodecs(); !slices.Equal(got, []string{"acme.xchacha", "acme.xml"}) {
		t.Errorf("FactoryCodecs %v", got)
	}
	if err := ValidateCodecOwner(s, "acme"); err != nil {
		t.Error(err)
	}
	if err := ValidateCodecOwner(s, "acme-2"); err == nil || !strings.Contains(err.Error(), `codec "acme.xchacha" is not module "acme-2"'s`) {
		t.Errorf("another module's: %v", err)
	}
	if !CodecOwner("acme.x", "acme") || CodecOwner("acme.", "acme") || CodecOwner("acmex.y", "acme") || CodecOwner("x", "") {
		t.Error("CodecOwner")
	}

	c := BuildCodec{Growth: 250, Overhead: 200}
	if c.Bound(1000) != 2700 || c.CallTimeout() != DefaultCodecTimeout {
		t.Errorf("bound %d, timeout %s", c.Bound(1000), c.CallTimeout())
	}
	if c.Timeout = "12s"; c.CallTimeout() != 12*time.Second {
		t.Error(c.CallTimeout())
	}
}

func TestValidateAgentlessCodecs(t *testing.T) {
	agentless := func(module, kind string) bool { return module == "dns" && kind == KindReverseCall }
	s := exampleBuildSchema(t)
	if err := ValidateAgentlessCodecs(s, agentless); err != nil {
		t.Fatalf("core's codec: %v", err)
	}
	// linux-elf connects through dns: JSON is not what an agentless channel
	// speaks; shellcode connects through http alone.
	s.Targets[2].Envelope = EnvelopeJSON
	if err := ValidateAgentlessCodecs(s, agentless); err == nil || !strings.Contains(err.Error(), `target "linux-elf": channel "dns"`) {
		t.Fatalf("json through an agentless kind: %v", err)
	}
	s = exampleBuildSchema(t)
	s.Targets[3].Crypto = "acme.x"
	if err := ValidateAgentlessCodecs(s, agentless); err != nil {
		t.Fatalf("a target narrowed to http: %v", err)
	}
	s.Crypto = "acme.x"
	if err := ValidateAgentlessCodecs(s, agentless); err == nil {
		t.Fatal("a factory's suite through an agentless kind")
	}
}

func TestValidateBuildRequestCodec(t *testing.T) {
	s, r := exampleBuildSchema(t), exampleBuildRequest(t)
	s.Targets[0].Envelope = EnvelopeJSON
	if p := ValidateBuildRequest(s, r); p["envelope"] != `"cbor" is not the target's "json"` || len(p) != 1 {
		t.Fatalf("envelope missing: %v", p)
	}
	r.Envelope = EnvelopeJSON
	if p := ValidateBuildRequest(s, r); p != nil {
		t.Fatalf("json: %v", p)
	}

	s, r = exampleBuildSchema(t), exampleBuildRequest(t)
	if r.Envelope = EnvelopeCBOR; ValidateBuildRequest(s, r) != nil {
		t.Fatal("cbor named")
	}
	s.Targets[0].Crypto, s.Codec = "acme.xchacha", &BuildCodec{Growth: 120}
	if p := ValidateBuildRequest(s, r); p["crypto"] != `suite "aes-256-cbc-hmac-sha256" is not the target's "acme.xchacha"` {
		t.Fatalf("the target's suite: %v", p)
	}
	material, _ := json.Marshal([]byte("factory key material"))
	r.Crypto = &BuildCrypto{Suite: "acme.xchacha", Material: material}
	if p := ValidateBuildRequest(s, r); p != nil {
		t.Fatalf("a factory's suite: %v", p)
	}
}
