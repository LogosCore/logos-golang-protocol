package protocol

import (
	"bytes"
	"strings"
	"testing"
)

// testKeys are an agentless call's keys.
var testKeys = &LinkKeys{Suite: CryptoAES256CBCHMACSHA256,
	Material: AES256CBCHMACSHA256Material{EncKey: bytes.Repeat([]byte{1}, 32), MACKey: bytes.Repeat([]byte{2}, 32)}}

func TestLinkFrameRoundTrip(t *testing.T) {
	id := bytes.Repeat([]byte{7}, 16)
	frames := []LinkFrame{
		{Type: LinkCall, Request: 5, Values: map[string]any{"host": "h"}, ID: id, Data: []byte{1}, Keys: testKeys},
		{Type: LinkOpen, Request: 6, Values: map[string]any{"host": "h"}, Under: id, Keys: testKeys},
		{Type: LinkCall, Request: 1, Values: map[string]any{"url": "http://x/a.php", "tls_verify": true}, ID: id, Data: []byte{1, 2}, Deadline: 30000},
		{Type: LinkOpen, Request: 2, Values: map[string]any{"host": "10.0.0.1"}},
		{Type: LinkOpen, Request: 3, Values: map[string]any{"host": "10.0.0.1"}, Under: id},
		{Type: LinkAnswer, Request: 1, ID: id, Data: []byte{3}, Status: 200},
		{Type: LinkAnswer, Request: 1, ID: id, Data: []byte{3}, Status: 200, Peer: "203.0.113.7"},
		{Type: LinkAnswer, Request: 1, Status: 404, Excerpt: []byte("<html>"), Peer: "2001:db8::1"},
		{Type: LinkAnswer, Request: 1, Failure: &LinkFailure{Kind: LinkFailTimeout, Msg: "no answer in 30s"}},
		{Type: LinkAnswer, Request: 1, Status: 404, Excerpt: []byte("<html>")},
	}
	for _, f := range frames {
		b, err := EncodeLinkFrame(f)
		if err != nil {
			t.Fatalf("encode %+v: %v", f, err)
		}
		got, err := DecodeLinkFrame(b)
		if err != nil {
			t.Fatalf("decode %+v: %v", f, err)
		}
		if got.Type != f.Type || got.Request != f.Request || !bytes.Equal(got.ID, f.ID) || !bytes.Equal(got.Data, f.Data) ||
			got.Status != f.Status || !bytes.Equal(got.Excerpt, f.Excerpt) || len(got.Values) != len(f.Values) || !bytes.Equal(got.Under, f.Under) ||
			(f.Keys != nil && (got.Keys == nil || got.Keys.Suite != f.Keys.Suite || !bytes.Equal(got.Keys.Material.EncKey, f.Keys.Material.EncKey) ||
				!bytes.Equal(got.Keys.Material.MACKey, f.Keys.Material.MACKey))) {
			t.Fatalf("round trip: got %+v, want %+v", got, f)
		}
	}
}

func TestLinkFrameRefused(t *testing.T) {
	id := bytes.Repeat([]byte{7}, 16)
	bad := map[string]LinkFrame{
		"no request":          {Type: LinkCall, ID: id, Data: []byte{1}},
		"call short id":       {Type: LinkCall, Request: 1, ID: id[:8], Data: []byte{1}},
		"call no data":        {Type: LinkCall, Request: 1, ID: id},
		"call with status":    {Type: LinkCall, Request: 1, ID: id, Data: []byte{1}, Status: 200},
		"open with data":      {Type: LinkOpen, Request: 1, Data: []byte{1}},
		"open with an id":     {Type: LinkOpen, Request: 1, ID: id},
		"open short under":    {Type: LinkOpen, Request: 1, Under: id[:8]},
		"call with under":     {Type: LinkCall, Request: 1, ID: id, Data: []byte{1}, Under: id},
		"answer with under":   {Type: LinkAnswer, Request: 1, Status: 404, Under: id},
		"answer with keys":    {Type: LinkAnswer, Request: 1, Status: 404, Keys: testKeys},
		"open keys, no under": {Type: LinkOpen, Request: 1, Keys: testKeys},
		"call unknown suite": {Type: LinkCall, Request: 1, ID: id, Data: []byte{1},
			Keys: &LinkKeys{Suite: "rot13", Material: testKeys.Material}},
		"call short keys": {Type: LinkCall, Request: 1, ID: id, Data: []byte{1},
			Keys: &LinkKeys{Suite: CryptoAES256CBCHMACSHA256, Material: AES256CBCHMACSHA256Material{EncKey: []byte{1}, MACKey: []byte{2}}}},
		"answer id alone":      {Type: LinkAnswer, Request: 1, ID: id},
		"answer with values":   {Type: LinkAnswer, Request: 1, Values: map[string]any{"a": 1}},
		"answer two outcomes":  {Type: LinkAnswer, Request: 1, ID: id, Data: []byte{1}, Failure: &LinkFailure{Kind: 1}},
		"failure with status":  {Type: LinkAnswer, Request: 1, Status: 500, Failure: &LinkFailure{Kind: 1}},
		"failure unknown kind": {Type: LinkAnswer, Request: 1, Failure: &LinkFailure{Kind: 9}},
		"failure long message": {Type: LinkAnswer, Request: 1, Failure: &LinkFailure{Kind: 1, Msg: strings.Repeat("x", MaxLinkFailureMsg+1)}},
		"excerpt too long":     {Type: LinkAnswer, Request: 1, Status: 404, Excerpt: make([]byte, MaxLinkExcerpt+1)},
		"peer not an address":  {Type: LinkAnswer, Request: 1, Status: 404, Peer: "example.com"},
		"peer on a failure":    {Type: LinkAnswer, Request: 1, Failure: &LinkFailure{Kind: 1}, Peer: "203.0.113.7"},
		"peer on a call":       {Type: LinkCall, Request: 1, ID: id, Data: []byte{1}, Peer: "203.0.113.7"},
		"unknown type":         {Type: 9, Request: 1},
	}
	for name, f := range bad {
		if _, err := EncodeLinkFrame(f); err == nil {
			t.Errorf("%s: encoded", name)
		}
	}
	if _, err := DecodeLinkFrame([]byte{0xff}); err == nil {
		t.Error("garbage decoded")
	}
	// An agentless channel's refusals are failures of their own kinds.
	for _, kind := range []int{LinkFailLogin, LinkFailHostKey} {
		if _, err := EncodeLinkFrame(LinkFrame{Type: LinkAnswer, Request: 1, Failure: &LinkFailure{Kind: kind, Msg: "refused"}}); err != nil {
			t.Errorf("failure kind %d: %v", kind, err)
		}
	}
}

func TestExcerpt(t *testing.T) {
	if got := Excerpt(make([]byte, 2000)); len(got) != MaxLinkExcerpt {
		t.Fatalf("excerpt of %d bytes", len(got))
	}
	if got := Excerpt([]byte("ab")); string(got) != "ab" {
		t.Fatalf("excerpt %q", got)
	}
}

func TestTargetValues(t *testing.T) {
	s := ConnectionSchema{SchemaVersion: ConnectionSchemaV2, Version: 1, Kinds: map[string]ConnectionKind{
		KindReverseCall: {Fields: []FieldSpec{{Key: "base_url", Type: FieldURL, Label: "Base URL", Required: true}}},
		KindBindCall: {
			Fields: []FieldSpec{{Key: "method", Type: FieldEnum, Label: "Method", Options: []EnumOption{{Value: "POST", Label: "POST"}}, Default: "POST"}},
			Target: []FieldSpec{
				{Key: "url", Type: FieldURL, Label: "URL", Required: true},
				{Key: "tls_verify", Type: FieldBool, Label: "Verify", Default: false},
			},
		},
	}}
	if err := ValidateConnectionSchema(s); err != nil {
		t.Fatal(err)
	}
	if p := ValidateTargetValues(s, KindBindCall, map[string]any{"url": "https://h/p.php"}); p != nil {
		t.Fatalf("valid target: %v", p)
	}
	if p := ValidateTargetValues(s, KindBindCall, map[string]any{}); p["url"] == "" {
		t.Fatalf("missing url not reported: %v", p)
	}
	if p := ValidateTargetValues(s, KindBindCall, map[string]any{"url": "https://h/p.php", "method": "GET"}); p["method"] == "" {
		t.Fatalf("a built-in field taken as a target's: %v", p)
	}
	if p := ValidateTargetValues(s, KindReverseCall, map[string]any{}); p[""] == "" {
		t.Fatalf("a reverse kind has targets: %v", p)
	}
	got := ResolveTargetValues(s, KindBindCall, map[string]any{"url": "https://h/p.php"})
	if got["url"] != "https://h/p.php" || got["tls_verify"] != false {
		t.Fatalf("resolved %v", got)
	}
	if !IsBindKind(KindBindCall) || IsBindKind(KindReversePersistent) {
		t.Fatal("IsBindKind")
	}
}

func TestRehelloItemName(t *testing.T) {
	if ItemName(ItemRehello) != "rehello" {
		t.Fatal(ItemName(ItemRehello))
	}
}

// An open's under travels in a key of its own: a channel that knows no
// under (its frame without the field) decodes the open, and the rest of it.
func TestLinkOpenUnderIsSkippable(t *testing.T) {
	b, err := EncodeLinkFrame(LinkFrame{Type: LinkOpen, Request: 4, Values: map[string]any{"host": "h"}, Under: bytes.Repeat([]byte{7}, 16)})
	if err != nil {
		t.Fatal(err)
	}
	var old struct {
		Type    int            `cbor:"0,keyasint"`
		Request uint64         `cbor:"1,keyasint"`
		Values  map[string]any `cbor:"2,keyasint,omitempty"`
		ID      []byte         `cbor:"3,keyasint,omitempty"`
	}
	if err := cborDec.Unmarshal(b, &old); err != nil || old.Type != LinkOpen || old.Request != 4 || old.ID != nil || old.Values["host"] != "h" {
		t.Fatalf("an older decoder: %+v (%v)", old, err)
	}
}
